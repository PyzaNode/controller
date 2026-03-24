package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pyzanode/controller/internal/cloudflare"
	"github.com/pyzanode/controller/internal/hub"
	"github.com/pyzanode/shared/debuglog"
	"github.com/pyzanode/shared/types"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

var oncePackageSync sync.Once

// HandleAgentWS handles WebSocket connection from an agent.
func (a *API) HandleAgentWS(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" || !a.auth.ValidateAgentToken(token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// First message from agent must be register { type, hostname, os, address? }
		var register struct {
			Type     string `json:"type"`
			Hostname string `json:"hostname"`
			OS       string `json:"os"`
			Address  string `json:"address"` // LAN IP (e.g. 10.0.0.110) so proxies on same network can reach backends
		}
		if err := conn.ReadJSON(&register); err != nil || register.Type != "register" {
			conn.WriteJSON(map[string]string{"error": "expected register message"})
			return
		}
		node := a.store.NodeRegister(register.Hostname, register.OS, strings.TrimSpace(register.Address))
		conn.WriteJSON(map[string]interface{}{"type": "registered", "node_id": node.ID})
		log.Printf("Node connected: %s (%s)", register.Hostname, node.ID)
		debuglog.Printf("[ws] node registered: hostname=%s node_id=%s", register.Hostname, node.ID)
		a.store.RecordAnalyticsEvent(&types.AnalyticsEvent{
			Type:    "node_connected",
			NodeID:  node.ID,
			Node:    node.Hostname,
			Message: "Node connected",
		})

		ac := h.Register(node.ID, conn)
		go h.RunAgent(ac)

		// Send preset packages to the node so it can build Docker images in the background (new-node sync).
		var syncPackages []struct {
			PresetID    string `json:"preset_id"`
			DockerImage string `json:"docker_image"`
		}
		packagesDir := filepath.Join(a.store.DataDir(), "packages")
		for _, p := range a.store.PresetsList() {
			if p.Type != "docker" || p.DockerImage == "" {
				continue
			}
			if _, err := os.Stat(filepath.Join(packagesDir, p.ID+".zip")); err == nil {
				syncPackages = append(syncPackages, struct {
					PresetID    string `json:"preset_id"`
					DockerImage string `json:"docker_image"`
				}{p.ID, p.DockerImage})
			}
		}
		if len(syncPackages) > 0 {
			_ = h.SendCommand(node.ID, "sync_packages", map[string]interface{}{"packages": syncPackages})
			debuglog.Printf("[ws] sent sync_packages to node %s: %d package(s)", node.ID, len(syncPackages))
		}

		a.startPackageSyncTickerIfNeeded()

		// server_id -> player_name(lower) -> uuid
		playerUUIDByServer := make(map[string]map[string]string)

		for {
			var msg struct {
				Type    string          `json:"type"`
				Payload json.RawMessage `json:"payload"`
			}
			if err := conn.ReadJSON(&msg); err != nil {
				break
			}
			debuglog.Printf("[ws] from node %s: type=%s", node.Hostname, msg.Type)
			switch msg.Type {
			case "heartbeat":
				var metrics types.NodeMetrics
				if err := json.Unmarshal(msg.Payload, &metrics); err != nil {
					continue
				}
				a.store.NodeUpdateMetrics(node.ID, &metrics, a.controllerVersion)
				managedIDs := make(map[string]bool)
				for _, s := range metrics.Servers {
					managedIDs[s.ServerID] = true
					a.store.ServerUpdateMetrics(s.ServerID, &s)
				}
				servers := a.store.ServersByNode(node.ID)
				running := 0
				now := time.Now()
				for _, sv := range servers {
					if sv.Status == "running" {
						running++
					}
					// Reconcile: agent doesn't have this server (container/process gone) → remove from dashboard.
					// Only delete when status is "running" and missing from heartbeat. Do NOT delete "starting"
					// servers; the agent may still be bringing the container up, so a heartbeat can arrive
					// before the server is in metrics.Servers, which would delete the record and leave an orphan container.
					// Only reap servers that have been empty (PlayerCount==0) for a grace period, so we don't
					// delete active sessions if a heartbeat misses a process briefly.
					if sv.Status != "running" || managedIDs[sv.ID] {
						continue
					}
					// Never delete servers that still report players online.
					if sv.PlayerCount > 0 {
						continue
					}
					// Require LastEmptyAt to be set and old enough before treating as stale.
					if sv.LastEmptyAt.IsZero() {
						continue
					}
					const staleServerGrace = 60 * time.Second
					if now.Sub(sv.LastEmptyAt) >= staleServerGrace {
						a.store.ServerDelete(sv.ID)
					}
				}
				a.store.NodeSetRunningCount(node.ID, running)
			case "server_status":
				var status struct {
					ServerID string `json:"server_id"`
					Status   string `json:"status"`
				}
				if err := json.Unmarshal(msg.Payload, &status); err != nil {
					continue
				}
				sv := a.store.ServerByID(status.ServerID)
				proxyGroupID := ""
				var serverName string
				if sv != nil {
					proxyGroupID = sv.ProxyGroupID
					serverName = sv.Name
				}
				// Container/process gone (stopped, killed, or removed via Docker Desktop/SSH): remove from dashboard
				if status.Status == "stopped" || status.Status == "crashed" {
					a.store.ServerDelete(status.ServerID)
					if sv != nil {
						a.store.RecordAnalyticsEvent(&types.AnalyticsEvent{
							Type:      "server_stopped",
							NetworkID: a.serverNetworkID(sv),
							ServerID:  sv.ID,
							Server:    sv.Name,
							NodeID:    sv.NodeID,
							Message:   "Server stopped/crashed",
						})
					}
					// Optional crash notification via ntfy.
					if status.Status == "crashed" {
						st := a.store.GetSettings()
						if st.NotifyOnCrash && st.NtfyURL != "" && st.NtfyTopic != "" {
							go sendNtfy(st.NtfyURL, st.NtfyTopic, fmt.Sprintf("Server crashed: %s", serverName), st.NtfyToken, st.NtfyUsername, st.NtfyPassword)
						}
					}
					if proxyGroupID != "" {
						go cloudflare.SyncSRV(a.store, proxyGroupID)
					}
				} else {
					a.store.ServerSetStatus(status.ServerID, status.Status)
					if sv != nil && status.Status == "running" {
						a.store.RecordAnalyticsEvent(&types.AnalyticsEvent{
							Type:      "server_started",
							NetworkID: a.serverNetworkID(sv),
							ServerID:  sv.ID,
							Server:    sv.Name,
							NodeID:    sv.NodeID,
							Message:   "Server is running",
						})
					}
					// Keep Cloudflare SRV in sync when proxies come online.
					if proxyGroupID != "" && status.Status == "running" {
						go cloudflare.SyncSRV(a.store, proxyGroupID)
					}
				}
			case "server_metrics":
				var m types.ServerMetrics
				if err := json.Unmarshal(msg.Payload, &m); err != nil {
					continue
				}
				a.store.ServerUpdateMetrics(m.ServerID, &m)
			case "node_alert":
				var payload struct {
					Message string `json:"message"`
				}
				if err := json.Unmarshal(msg.Payload, &payload); err != nil {
					continue
				}
				a.store.NodeSetAlert(node.ID, payload.Message)
			case "server_log":
				var payload struct {
					ServerID string `json:"server_id"`
					Line     string `json:"line"`
				}
				if err := json.Unmarshal(msg.Payload, &payload); err != nil {
					continue
				}
				if sv := a.store.ServerByID(payload.ServerID); sv != nil {
					if evType, player, msg, playerUUID := parseMinecraftLogEvent(payload.Line); evType != "" {
						meta := map[string]string{}
						if playerUUID != "" {
							meta["player_uuid"] = strings.ToLower(playerUUID)
							if player != "" {
								if playerUUIDByServer[payload.ServerID] == nil {
									playerUUIDByServer[payload.ServerID] = make(map[string]string)
								}
								playerUUIDByServer[payload.ServerID][strings.ToLower(player)] = strings.ToLower(playerUUID)
							}
						} else if player != "" {
							if m := playerUUIDByServer[payload.ServerID]; m != nil {
								if u := m[strings.ToLower(player)]; u != "" {
									meta["player_uuid"] = u
								}
							}
						}
						a.store.RecordAnalyticsEvent(&types.AnalyticsEvent{
							Type:      evType,
							NetworkID: a.serverNetworkID(sv),
							ServerID:  sv.ID,
							Server:    sv.Name,
							NodeID:    sv.NodeID,
							Player:    player,
							Message:   msg,
							Metadata:  meta,
						})
					}
				}
				// Append to per-server log file for previous-run viewing.
				appendServerLogLine(a.store.DataDir(), payload.ServerID, payload.Line)
				if a.logStream != nil {
					a.logStream.Broadcast(payload.ServerID, payload.Line)
				}
			default:
				log.Printf("agent ws: unknown type %s", msg.Type)
				debuglog.Printf("[ws] unknown message type from %s: %s", node.Hostname, msg.Type)
			}
		}
		debuglog.Printf("[ws] node disconnected: %s (%s)", node.Hostname, node.ID)
		log.Printf("Node disconnected: %s (%s)", node.Hostname, node.ID)
		// Mark node offline and immediately purge any servers assigned to it so
		// stale instances are not counted in metrics or shown in the dashboard.
		a.store.NodeSetOffline(node.ID)
		a.store.NodePurgeServers(node.ID)
		a.store.RecordAnalyticsEvent(&types.AnalyticsEvent{
			Type:    "node_disconnected",
			NodeID:  node.ID,
			Node:    node.Hostname,
			Message: "Node disconnected",
		})
		// Optional node disconnect notification via ntfy.
		st := a.store.GetSettings()
		if st.NotifyOnNodeDisconnect && st.NtfyURL != "" && st.NtfyTopic != "" {
			go sendNtfy(st.NtfyURL, st.NtfyTopic, fmt.Sprintf("Node disconnected: %s", node.Hostname), st.NtfyToken, st.NtfyUsername, st.NtfyPassword)
		}
		h.Unregister(node.ID)
	}
}

// appendServerLogLine appends a single log line to a per-server log file under dataDir/logs.
func appendServerLogLine(dataDir, serverID, line string) {
	if dataDir == "" || serverID == "" {
		return
	}
	logsDir := filepath.Join(dataDir, "logs")
	if err := os.MkdirAll(logsDir, 0750); err != nil {
		return
	}
	path := filepath.Join(logsDir, serverID+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line + "\n")
}

// sendNtfy sends a simple text notification to an ntfy topic.
// Auth: if token is set, use Bearer; else if username and password are set, use HTTP Basic.
func sendNtfy(baseURL, topic, message, token, username, password string) {
	if baseURL == "" || topic == "" || message == "" {
		return
	}
	url := strings.TrimRight(baseURL, "/") + "/" + topic
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBufferString(message))
	if err != nil {
		return
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	} else if username != "" && password != "" {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

func parseMinecraftLogEvent(line string) (eventType, player, message, playerUUID string) {
	l := strings.TrimSpace(line)
	if l == "" {
		return "", "", "", ""
	}

	// Vanilla/Paper: "UUID of player Name is xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
	if i := strings.Index(l, "UUID of player "); i >= 0 {
		rest := l[i+len("UUID of player "):]
		parts := strings.SplitN(rest, " is ", 2)
		if len(parts) == 2 {
			name := normalizePlayerName(parts[0])
			uuid := strings.TrimSpace(parts[1])
			if isLikelyPlayerName(name) && isLikelyUUID(uuid) {
				return "player_uuid", name, "Player UUID resolved", strings.ToLower(uuid)
			}
		}
	}

	// Velocity style: [connected player] Name (...) has connected/disconnected
	if i := strings.Index(l, "[connected player] "); i >= 0 {
		rest := l[i+len("[connected player] "):]
		if j := strings.Index(rest, " ("); j > 0 {
			name := normalizePlayerName(rest[:j])
			if strings.Contains(rest, " has connected") {
				if isLikelyPlayerName(name) {
					return "player_join", name, "Player joined", ""
				}
			}
			if strings.Contains(rest, " has disconnected") {
				if isLikelyPlayerName(name) {
					return "player_leave", name, "Player left", ""
				}
			}
		}
	}
	// Vanilla/Paper style: Name joined the game / left the game
	if idx := strings.Index(l, " joined the game"); idx > 0 {
		name := normalizePlayerName(extractLogMessagePrefix(l[:idx]))
		if isLikelyPlayerName(name) {
			return "player_join", name, "Player joined", ""
		}
	}
	if idx := strings.Index(l, " left the game"); idx > 0 {
		name := normalizePlayerName(extractLogMessagePrefix(l[:idx]))
		if isLikelyPlayerName(name) {
			return "player_leave", name, "Player left", ""
		}
	}
	// Chat style: <Name> message
	if i := strings.Index(l, "<"); i >= 0 {
		if j := strings.Index(l[i+1:], ">"); j > 0 {
			name := normalizePlayerName(l[i+1 : i+1+j])
			msg := strings.TrimSpace(l[i+1+j+1:])
			if isLikelyPlayerName(name) && msg != "" {
				return "chat", name, msg, ""
			}
		}
	}
	return "", "", "", ""
}

func extractLogMessagePrefix(s string) string {
	// Drops common timestamp/level prefix "...]: " and keeps only message payload.
	if i := strings.LastIndex(s, "]: "); i >= 0 && i+3 < len(s) {
		return s[i+3:]
	}
	if i := strings.LastIndex(s, "] "); i >= 0 && i+2 < len(s) {
		return s[i+2:]
	}
	return s
}

func normalizePlayerName(s string) string {
	s = strings.TrimSpace(s)
	// Strip formatting artifacts commonly seen in proxy logs.
	s = strings.Trim(s, "[]()<>")
	return strings.TrimSpace(s)
}

func isLikelyPlayerName(s string) bool {
	if len(s) < 1 || len(s) > 16 {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			continue
		}
		return false
	}
	return true
}

func isLikelyUUID(s string) bool {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return false
			}
			continue
		}
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return false
	}
	return true
}

// HandleLogsWS handles WebSocket connection from the dashboard for live server log streaming.
// Query param: token (API/agent token). Client sends {"type":"subscribe_logs","server_id":"..."} to start; {"type":"unsubscribe_logs"} to stop.
// Server sends {"type":"server_log","payload":{"server_id":"...","line":"..."}} for each line.
func (a *API) HandleLogsWS() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if _, err := a.auth.ValidateJWT(token); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		var currentServerID string
		var recvCh chan string

		readDone := make(chan struct{})
		go func() {
			defer close(readDone)
			for {
				var msg struct {
					Type     string `json:"type"`
					ServerID string `json:"server_id"`
				}
				if err := conn.ReadJSON(&msg); err != nil {
					return
				}
				switch msg.Type {
				case "subscribe_logs":
					if recvCh != nil && currentServerID != "" {
						a.logStream.Unsubscribe(currentServerID, recvCh)
					}
					currentServerID = msg.ServerID
					if currentServerID == "" {
						continue
					}
					recent, ch := a.logStream.Subscribe(currentServerID)
					recvCh = ch
					subID := currentServerID
					for _, line := range recent {
						conn.WriteJSON(map[string]interface{}{
							"type":    "server_log",
							"payload": map[string]string{"server_id": subID, "line": line},
						})
					}
					go func() {
						for line := range ch {
							conn.WriteJSON(map[string]interface{}{
								"type":    "server_log",
								"payload": map[string]string{"server_id": subID, "line": line},
							})
						}
					}()
				case "unsubscribe_logs":
					if recvCh != nil && currentServerID != "" {
						a.logStream.Unsubscribe(currentServerID, recvCh)
						recvCh = nil
						currentServerID = ""
					}
				}
			}
		}()

		<-readDone
		if recvCh != nil && currentServerID != "" {
			a.logStream.Unsubscribe(currentServerID, recvCh)
		}
	}
}

// startPackageSyncTickerIfNeeded starts a single background goroutine that every 60s sends sync_packages to all connected nodes.
func (a *API) startPackageSyncTickerIfNeeded() {
	oncePackageSync.Do(func() {
		go a.runPackageSyncTicker()
	})
}

func (a *API) runPackageSyncTicker() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if a.hub == nil {
			continue
		}
		var syncPackages []struct {
			PresetID    string `json:"preset_id"`
			DockerImage string `json:"docker_image"`
		}
		packagesDir := filepath.Join(a.store.DataDir(), "packages")
		for _, p := range a.store.PresetsList() {
			if p.Type != "docker" || p.DockerImage == "" {
				continue
			}
			if _, err := os.Stat(filepath.Join(packagesDir, p.ID+".zip")); err == nil {
				syncPackages = append(syncPackages, struct {
					PresetID    string `json:"preset_id"`
					DockerImage string `json:"docker_image"`
				}{p.ID, p.DockerImage})
			}
		}
		if len(syncPackages) == 0 {
			continue
		}
		payload := map[string]interface{}{"packages": syncPackages}
		nodeIDs := a.hub.NodeIDs()
		for _, nodeID := range nodeIDs {
			_ = a.hub.SendCommand(nodeID, "sync_packages", payload)
		}
		debuglog.Printf("[ws] sync_packages broadcast to %d node(s), %d package(s)", len(nodeIDs), len(syncPackages))
	}
}
