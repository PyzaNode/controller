package api

import (
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pyzanode/shared/types"
)

// runScalerLoop runs in the background and ensures server groups and proxy groups meet min/always-one.
func (a *API) runScalerLoop() {
	tick := time.NewTicker(45 * time.Second)
	defer tick.Stop()
	for range tick.C {
		a.scalerMu.Lock()
		a.scaleServerGroups()
		a.scaleProxyGroups()
		a.cleanupStoppedByGroupName()
		a.shutdownIdleServers()
		a.scalerMu.Unlock()
	}
}

// shutdownIdleServers stops extra running servers (above min) that have had 0 players for IdleShutdownSec.
func (a *API) shutdownIdleServers() {
	for _, g := range a.store.ServerGroupsList() {
		idleSec := g.IdleShutdownSec
		if idleSec <= 0 {
			continue
		}
		min := g.MinServers
		if g.AlwaysKeepOneOnline && min < 1 {
			min = 1
		}
		servers := a.store.ServersByServerGroup(g.ID)
		var running []*types.Server
		for _, sv := range servers {
			if sv.Status == "running" && sv.ServerGroupID == g.ID {
				running = append(running, sv)
			}
		}
		if len(running) <= min {
			continue
		}
		sort.Slice(running, func(i, j int) bool {
			ti, tj := running[i].LastEmptyAt, running[j].LastEmptyAt
			if ti.IsZero() {
				ti = time.Now()
			}
			if tj.IsZero() {
				tj = time.Now()
			}
			return ti.Before(tj)
		})
		threshold := time.Now().Add(-time.Duration(idleSec) * time.Second)
		toStop := len(running) - min
		for i := 0; i < toStop && i < len(running); i++ {
			sv := running[i]
			if sv.PlayerCount > 0 {
				continue
			}
			emptySince := sv.LastEmptyAt
			if emptySince.IsZero() {
				emptySince = time.Now()
			}
			if !emptySince.Before(threshold) {
				continue
			}
			if a.hub != nil {
				a.hub.SendCommand(sv.NodeID, "stop_server", map[string]string{"server_id": sv.ID})
			}
		}
	}
}

// cleanupStoppedByGroupName removes stopped/crashed servers in a group when that group still has
// at least one running or starting server, so the list doesn’t grow when you stop temp servers.
func (a *API) cleanupStoppedByGroupName() {
	all := a.store.ServersList()
	groupNames := make(map[string]struct{})
	for _, sv := range all {
		if sv.Group != "" {
			groupNames[sv.Group] = struct{}{}
		}
	}
	for groupName := range groupNames {
		servers := a.store.ServersByGroup(groupName)
		runningOrStarting := 0
		var stopped []*types.Server
		for _, sv := range servers {
			if sv.Status == "running" || sv.Status == "starting" {
				runningOrStarting++
			} else if sv.Status == "stopped" || sv.Status == "crashed" {
				stopped = append(stopped, sv)
			}
		}
		// If the group still has something running, remove all stopped so the list doesn’t grow.
		if runningOrStarting >= 1 && len(stopped) > 0 {
			for _, sv := range stopped {
				a.store.ServerDelete(sv.ID)
			}
		}
	}
}

func (a *API) scaleServerGroups() {
	groups := a.store.ServerGroupsList()
	allNodes := a.store.NodesList()
	var nodes []*types.Node
	for _, n := range allNodes {
		if !a.nodeIsOffline(n.ID) {
			nodes = append(nodes, n)
		}
	}
	if len(nodes) == 0 {
		return
	}
	for _, g := range groups {
		preset := a.store.PresetByID(g.PresetID)
		if preset == nil {
			continue
		}
		usableNodes := filterNodesForPreset(nodes, preset)
		if len(usableNodes) == 0 {
			// All nodes are busy or unsuitable for this preset; fall back to all online nodes.
			usableNodes = nodes
		}
		for {
			servers := a.store.ServersByServerGroup(g.ID)
			running := 0
			for _, sv := range servers {
				if sv.Status == "running" || sv.Status == "starting" {
					running++
				}
			}
			min := g.MinServers
			if g.AlwaysKeepOneOnline && min < 1 {
				min = 1
			}
			if g.AllowScaleToZero && min == 0 {
				// could still have warm pool; for now just respect min
			}
			if running >= min {
				// Scale-down: remove excess stopped servers so the list doesn’t fill up
				if len(servers) > g.MaxServers {
					var stopped []*types.Server
					for _, sv := range servers {
						if sv.Status == "stopped" || sv.Status == "crashed" {
							stopped = append(stopped, sv)
						}
					}
					sort.Slice(stopped, func(i, j int) bool { return stopped[i].CreatedAt.Before(stopped[j].CreatedAt) })
					toRemove := len(servers) - g.MaxServers
					for i := 0; i < toRemove && i < len(stopped); i++ {
						a.store.ServerDelete(stopped[i].ID)
					}
				}
				break
			}
			need := min - running
			if need <= 0 {
				break
			}
			// Create one at a time and re-check so we never over-create or get duplicate ports/names.
			// Prefer nodes that are not currently downloading/building this preset's image.
			nodeID := usableNodes[running%len(usableNodes)].ID
			// Generate a unique name like "<group>-N" where N is the smallest positive
			// integer not currently used for this group's servers.
			serversInGroup := a.store.ServersByGroup(g.Name)
			usedOrdinals := make(map[int]bool)
			prefix := g.Name + "-"
			for _, sv := range serversInGroup {
				if strings.HasPrefix(sv.Name, prefix) {
					if n, err := strconv.Atoi(strings.TrimPrefix(sv.Name, prefix)); err == nil && n > 0 {
						usedOrdinals[n] = true
					}
				}
			}
			ordinal := 1
			for usedOrdinals[ordinal] {
				ordinal++
			}
			name := g.Name + "-" + strconv.Itoa(ordinal)
			sv, err := a.store.ServerCreate(name, g.PresetID, nodeID, 0, g.Name, g.NetworkID, g.ID, "", "")
			if err != nil {
				log.Printf("scaler: create server for group %s: %v", g.Name, err)
				break
			}
			if a.hub != nil {
				a.store.ServerSetStatus(sv.ID, "starting")
				payload := map[string]interface{}{"server_id": sv.ID, "preset": preset, "port": sv.Port}
				if a.store.GetSettings().AutoPortForwardUPnP {
					payload["port_forward_upnp"] = true
				}
				a.hub.SendCommand(sv.NodeID, "start_server", payload)
			}
		}
	}
}

func (a *API) scaleProxyGroups() {
	groups := a.store.ProxyGroupsList()
	allNodes := a.store.NodesList()
	var nodes []*types.Node
	for _, n := range allNodes {
		if !a.nodeIsOffline(n.ID) {
			nodes = append(nodes, n)
		}
	}
	if len(nodes) == 0 {
		return
	}
	for _, g := range groups {
		preset := a.store.PresetByID(g.PresetID)
		if preset == nil {
			continue
		}
		usableNodes := filterNodesForPreset(nodes, preset)
		if len(usableNodes) == 0 {
			usableNodes = nodes
		}
		for {
			servers := a.store.ServersByProxyGroup(g.ID)
			running := 0
			for _, sv := range servers {
				if sv.Status == "running" || sv.Status == "starting" {
					running++
				}
			}
			min := g.MinProxies
			if g.AlwaysOneOnline && min < 1 {
				min = 1
			}
			if running >= min {
				// Scale-down: remove excess stopped proxies so the list doesn’t fill up
				if len(servers) > g.MaxProxies {
					var stopped []*types.Server
					for _, sv := range servers {
						if sv.Status == "stopped" || sv.Status == "crashed" {
							stopped = append(stopped, sv)
						}
					}
					sort.Slice(stopped, func(i, j int) bool { return stopped[i].CreatedAt.Before(stopped[j].CreatedAt) })
					toRemove := len(servers) - g.MaxProxies
					for i := 0; i < toRemove && i < len(stopped); i++ {
						a.store.ServerDelete(stopped[i].ID)
					}
				}
				break
			}
			need := min - running
			if need <= 0 {
				break
			}
			// Create one at a time and re-check so we never over-create or get duplicate ports/names.
			nodeID := usableNodes[running%len(usableNodes)].ID
			// Generate a unique proxy name "<group>-N" similar to backend servers.
			serversInGroup := a.store.ServersByProxyGroup(g.ID)
			usedOrdinals := make(map[int]bool)
			prefix := g.Name + "-"
			for _, sv := range serversInGroup {
				if strings.HasPrefix(sv.Name, prefix) {
					if n, err := strconv.Atoi(strings.TrimPrefix(sv.Name, prefix)); err == nil && n > 0 {
						usedOrdinals[n] = true
					}
				}
			}
			ordinal := 1
			for usedOrdinals[ordinal] {
				ordinal++
			}
			name := g.Name + "-" + strconv.Itoa(ordinal)
			sv, err := a.store.ServerCreate(name, g.PresetID, nodeID, 0, g.Name, g.NetworkID, "", g.ID, "")
			if err != nil {
				log.Printf("scaler: create proxy for group %s: %v", g.Name, err)
				break
			}
			if a.hub != nil {
				a.store.ServerSetStatus(sv.ID, "starting")
				payload := map[string]interface{}{"server_id": sv.ID, "preset": preset, "port": sv.Port}
				if a.store.GetSettings().AutoPortForwardUPnP {
					payload["port_forward_upnp"] = true
				}
				a.hub.SendCommand(sv.NodeID, "start_server", payload)
			}
		}
	}
}

// filterNodesForPreset returns the subset of nodes that are suitable for running the given preset.
// For Docker presets, nodes that are currently downloading/building the preset's image are skipped
// so other nodes can be used while the image is prepared in the background.
func filterNodesForPreset(nodes []*types.Node, preset *types.Preset) []*types.Node {
	if preset == nil || preset.Type != "docker" || preset.ID == "" {
		return nodes
	}
	var out []*types.Node
	for _, n := range nodes {
		// Skip nodes that are currently downloading/building this preset image, or that have a Docker/daemon issue alert.
		if nodeBusyBuildingPreset(n, preset.ID) {
			continue
		}
		if nodeHasDockerIssue(n) {
			continue
		}
		out = append(out, n)
	}
	return out
}

// nodeBusyBuildingPreset returns true if this node's last alert indicates it is currently
// downloading/building the Docker image for the given preset.
func nodeBusyBuildingPreset(n *types.Node, presetID string) bool {
	if n == nil || n.Alert == "" || presetID == "" {
		return false
	}
	alert := n.Alert
	if !strings.Contains(alert, "Image ") {
		return false
	}
	if !strings.Contains(alert, " for preset "+presetID) {
		return false
	}
	if !strings.Contains(alert, "downloading/building") {
		return false
	}
	return true
}

// nodeHasDockerIssue returns true if the node's last alert suggests Docker is missing or the daemon/API is unavailable.
func nodeHasDockerIssue(n *types.Node) bool {
	if n == nil || n.Alert == "" {
		return false
	}
	alert := strings.ToLower(n.Alert)
	if strings.Contains(alert, "docker is not installed or not running") {
		return true
	}
	if strings.Contains(alert, "failed to connect to the docker api") {
		return true
	}
	return false
}
