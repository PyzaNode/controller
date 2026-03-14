package cloudflare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/pyzanode/controller/internal/store"
	"github.com/pyzanode/shared/debuglog"
)

const cfAPIBase = "https://api.cloudflare.com/client/v4"

var (
	// srvSyncMu serializes SRV sync per proxy group so concurrent syncs don't race (e.g. startup + proxy start).
	srvSyncMu   sync.Mutex
	srvSyncKeys = make(map[string]*sync.Mutex)
)

type targetPort struct {
	target string
	port   int
}

// SyncSRV updates Cloudflare DNS so _minecraft._tcp.<SRVHostname> SRV records
// match the current proxy group servers (target = node hostname, port = server port).
// proxyGroupID identifies which proxy group to sync (config comes from its network).
// It is safe to call from a goroutine. Logs errors but does not return (fire-and-forget).
func SyncSRV(s *store.Store, proxyGroupID string) {
	if proxyGroupID == "" {
		return
	}
	cfg := s.GetCloudflareSRVForSync(proxyGroupID)
	if cfg == nil {
		return
	}
	// Serialize per proxy group so we don't run two syncs for the same zone/host concurrently.
	srvSyncMu.Lock()
	keyMu, ok := srvSyncKeys[proxyGroupID]
	if !ok {
		keyMu = &sync.Mutex{}
		srvSyncKeys[proxyGroupID] = keyMu
	}
	keyMu.Lock()
	srvSyncMu.Unlock()
	defer keyMu.Unlock()

	log.Printf("[cloudflare-srv] sync starting: zone=%s host=%s proxy_group=%s target_override=%s", cfg.ZoneID, cfg.SRVHostname, cfg.ProxyGroupID, cfg.TargetHostname)
	debuglog.Printf("[cloudflare-srv] sync starting: zone=%s host=%s proxy_group=%s", cfg.ZoneID, cfg.SRVHostname, cfg.ProxyGroupID)
	servers := s.ServersByProxyGroup(cfg.ProxyGroupID)
	var entries []targetPort
	for _, sv := range servers {
		// Only publish SRV entries for online proxies.
		if sv.Status != "running" {
			continue
		}
		if sv.Port <= 0 {
			continue
		}
		target := ""
		// 1) Per-node override if set
		if node := s.NodeByID(sv.NodeID); node != nil {
			if node.PublicHostname != "" {
				target = node.PublicHostname
			} else if cfg.TargetHostname == "" {
				// Only fall back to OS hostname when no global target is set
				target = node.Hostname
			}
		}
		// 2) Global override from settings (wins over OS hostname)
		if cfg.TargetHostname != "" {
			target = cfg.TargetHostname
		}
		if target == "" {
			continue
		}
		entries = append(entries, targetPort{target: target, port: sv.Port})
	}
	log.Printf("[cloudflare-srv] found %d proxy servers for SRV sync", len(entries))
	debuglog.Printf("[cloudflare-srv] entries: %d targets for %s", len(entries), cfg.SRVHostname)
	for i, e := range entries {
		debuglog.Printf("[cloudflare-srv] entry %d: target=%s port=%d", i+1, e.target, e.port)
	}
	if err := syncSRVToCloudflare(cfg.ZoneID, cfg.APIToken, cfg.SRVHostname, entries); err != nil {
		log.Printf("[cloudflare-srv] sync failed: %v", err)
		debuglog.Printf("[cloudflare-srv] sync failed: %v", err)
	} else {
		debuglog.Printf("[cloudflare-srv] sync ok: %d SRV records", len(entries))
	}
}

// SyncSRVForAllNetworks runs SyncSRV for each network that has Cloudflare SRV enabled (e.g. on startup).
func SyncSRVForAllNetworks(s *store.Store) {
	for _, n := range s.NetworksList() {
		if n.CloudflareSRV != nil && n.CloudflareSRV.Enabled && n.CloudflareSRV.ProxyGroupID != "" {
			go SyncSRV(s, n.CloudflareSRV.ProxyGroupID)
		}
	}
}

type cfListResp struct {
	Result []struct {
		ID      string `json:"id"`
		Comment string `json:"comment"`
	} `json:"result"`
}

type cfCreateBody struct {
	Type    string     `json:"type"`
	Name    string     `json:"name"`
	Content string     `json:"content,omitempty"`
	Data    *cfSRVData `json:"data,omitempty"`
	TTL     int        `json:"ttl"`
	Comment string     `json:"comment,omitempty"`
}

type cfSRVData struct {
	Service  string `json:"service"`
	Proto    string `json:"proto"`
	Name     string `json:"name"`
	Priority int    `json:"priority"`
	Weight   int    `json:"weight"`
	Port     int    `json:"port"`
	Target   string `json:"target"`
}

func syncSRVToCloudflare(zoneID, apiToken, srvHostname string, entries []targetPort) error {
	client := &http.Client{Timeout: 30 * time.Second}
	srvName := "_minecraft._tcp." + srvHostname

	// List existing SRV records for this name
	listURL, _ := url.Parse(cfAPIBase + "/zones/" + zoneID + "/dns_records")
	q := listURL.Query()
	q.Set("type", "SRV")
	q.Set("name", srvName)
	listURL.RawQuery = q.Encode()
	log.Printf("[cloudflare-srv] listing SRV records: %s", listURL.String())
	req, _ := http.NewRequest(http.MethodGet, listURL.String(), nil)
	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("list SRV records: HTTP %d: %s", resp.StatusCode, string(body))
	}
	var listResp cfListResp
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return err
	}

	// Delete existing records that we previously created (comment marker)
	for _, rec := range listResp.Result {
		if rec.Comment != "pyzanode-managed" {
			continue
		}
		log.Printf("[cloudflare-srv] deleting managed SRV record id=%s", rec.ID)
		delReq, _ := http.NewRequest(http.MethodDelete,
			cfAPIBase+"/zones/"+zoneID+"/dns_records/"+rec.ID, nil)
		delReq.Header.Set("Authorization", "Bearer "+apiToken)
		delResp, err := client.Do(delReq)
		if err != nil {
			return fmt.Errorf("delete SRV record %s: %w", rec.ID, err)
		}
		body, _ := io.ReadAll(delResp.Body)
		delResp.Body.Close()
		if delResp.StatusCode != http.StatusOK && delResp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("delete SRV record %s: HTTP %d: %s", rec.ID, delResp.StatusCode, string(body))
		}
	}

	// Create one SRV record per proxy
	for i, e := range entries {
		target := e.target
		if target != "" && target[len(target)-1] != '.' {
			target = target + "."
		}
		body := cfCreateBody{
			Type: "SRV",
			Name: srvName,
			Data: &cfSRVData{
				Service:  "_minecraft",
				Proto:    "_tcp",
				Name:     srvHostname,
				Priority: 5,
				Weight:   0,
				Port:     e.port,
				Target:   target,
			},
			TTL:     60, // Minimum for Cloudflare non-Enterprise; proxies show up in DNS within ~1 min
			Comment: "pyzanode-managed",
		}
		raw, _ := json.Marshal(body)
		log.Printf("[cloudflare-srv] creating SRV #%d: name=%s target=%s port=%d", i+1, srvName, target, e.port)
		req, _ := http.NewRequest(http.MethodPost, cfAPIBase+"/zones/"+zoneID+"/dns_records", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+apiToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return fmt.Errorf("create SRV record %d: HTTP %d: %s", i+1, resp.StatusCode, string(body))
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	return nil
}
