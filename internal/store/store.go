package store

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pyzanode/shared/types"
)

type Store struct {
	mu           sync.RWMutex
	nodes        map[string]*types.Node
	servers      map[string]*types.Server
	presets      map[string]*types.Preset
	networks     map[string]*types.Network
	serverGroups map[string]*types.ServerGroup
	proxyGroups  map[string]*types.ProxyGroup
	analytics    []*types.AnalyticsEvent
	playerStats  map[string]*types.PlayerAnalytics // key: networkID|player
	settings     *types.Settings
	dataDir      string
}

func New(dataDir string) (*Store, error) {
	s := &Store{
		nodes:        make(map[string]*types.Node),
		servers:      make(map[string]*types.Server),
		presets:      make(map[string]*types.Preset),
		networks:     make(map[string]*types.Network),
		serverGroups: make(map[string]*types.ServerGroup),
		proxyGroups:  make(map[string]*types.ProxyGroup),
		analytics:    make([]*types.AnalyticsEvent, 0, 2048),
		playerStats:  make(map[string]*types.PlayerAnalytics),
		settings:     &types.Settings{},
		dataDir:      dataDir,
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	for _, name := range []string{"nodes.json", "servers.json", "presets.json", "networks.json", "server_groups.json", "proxy_groups.json", "settings.json", "analytics_events.json", "player_analytics.json"} {
		path := filepath.Join(s.dataDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		switch name {
		case "nodes.json":
			var list []*types.Node
			if err := json.Unmarshal(data, &list); err != nil {
				return err
			}
			for _, n := range list {
				s.nodes[n.ID] = n
			}
		case "servers.json":
			// Servers are treated as ephemeral runtime state. On controller startup,
			// discard any persisted servers.json so the dashboard starts with a clean slate.
			// New servers will be created by the scaler or API as needed.
			continue
		case "presets.json":
			var list []*types.Preset
			if err := json.Unmarshal(data, &list); err != nil {
				return err
			}
			for _, p := range list {
				s.presets[p.ID] = p
			}
		case "networks.json":
			var list []*types.Network
			if err := json.Unmarshal(data, &list); err != nil {
				return err
			}
			for _, n := range list {
				s.networks[n.ID] = n
			}
		case "server_groups.json":
			var list []*types.ServerGroup
			if err := json.Unmarshal(data, &list); err != nil {
				return err
			}
			for _, g := range list {
				s.serverGroups[g.ID] = g
			}
		case "proxy_groups.json":
			var list []*types.ProxyGroup
			if err := json.Unmarshal(data, &list); err != nil {
				return err
			}
			for _, g := range list {
				s.proxyGroups[g.ID] = g
			}
		case "settings.json":
			var st types.Settings
			if err := json.Unmarshal(data, &st); err != nil {
				return err
			}
			s.settings = &st
		case "analytics_events.json":
			var list []*types.AnalyticsEvent
			if err := json.Unmarshal(data, &list); err != nil {
				return err
			}
			s.analytics = list
		case "player_analytics.json":
			var m map[string]*types.PlayerAnalytics
			if err := json.Unmarshal(data, &m); err != nil {
				return err
			}
			s.playerStats = m
		}
	}
	if s.analytics == nil {
		s.analytics = make([]*types.AnalyticsEvent, 0, 2048)
	}
	if s.playerStats == nil {
		s.playerStats = make(map[string]*types.PlayerAnalytics)
	}
	return nil
}

func (s *Store) save(name string, v interface{}) error {
	path := filepath.Join(s.dataDir, name)
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// saveNodes/saveServers/savePresets must be called with s.mu held (Lock or RLock).
// They do not take the lock themselves to avoid deadlock when called from a method that already holds Lock.
func (s *Store) saveNodes() error {
	list := make([]*types.Node, 0, len(s.nodes))
	for _, n := range s.nodes {
		list = append(list, n)
	}
	return s.save("nodes.json", list)
}

func (s *Store) saveServers() error {
	list := make([]*types.Server, 0, len(s.servers))
	for _, sv := range s.servers {
		list = append(list, sv)
	}
	return s.save("servers.json", list)
}

func (s *Store) savePresets() error {
	list := make([]*types.Preset, 0, len(s.presets))
	for _, p := range s.presets {
		list = append(list, p)
	}
	return s.save("presets.json", list)
}

func (s *Store) saveNetworks() error {
	list := make([]*types.Network, 0, len(s.networks))
	for _, n := range s.networks {
		list = append(list, n)
	}
	return s.save("networks.json", list)
}

func (s *Store) saveServerGroups() error {
	list := make([]*types.ServerGroup, 0, len(s.serverGroups))
	for _, g := range s.serverGroups {
		list = append(list, g)
	}
	return s.save("server_groups.json", list)
}

func (s *Store) saveProxyGroups() error {
	list := make([]*types.ProxyGroup, 0, len(s.proxyGroups))
	for _, g := range s.proxyGroups {
		list = append(list, g)
	}
	return s.save("proxy_groups.json", list)
}

// Nodes
func (s *Store) NodeByID(id string) *types.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodes[id]
}

// NodeSetAddress sets the node's local/LAN address (e.g. 10.0.0.110) for proxies on the same network.
func (s *Store) NodeSetAddress(id, address string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := s.nodes[id]; n != nil {
		n.Address = address
		_ = s.saveNodes()
	}
}

// NodeSetPublicHostname updates the public hostname for a node and persists nodes.json.
func (s *Store) NodeSetPublicHostname(id, publicHostname string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := s.nodes[id]; n != nil {
		n.PublicHostname = publicHostname
		_ = s.saveNodes()
	}
}

// NodeSetUsePublicHostname sets whether proxies should use this node's public hostname for backends (true) or address/hostname (false, for NAT/same network).
func (s *Store) NodeSetUsePublicHostname(id string, use bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := s.nodes[id]; n != nil {
		u := use
		n.UsePublicHostname = &u
		_ = s.saveNodes()
	}
}

// nodeByHostname returns a node with the given hostname; must be called with s.mu held.
func (s *Store) nodeByHostname(hostname string) *types.Node {
	for _, n := range s.nodes {
		if n.Hostname == hostname {
			return n
		}
	}
	return nil
}

func (s *Store) NodeRegister(hostname, osName, address string) *types.Node {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Reuse existing node with same hostname (reconnect) so ID and server assignments stay
	if n := s.nodeByHostname(hostname); n != nil {
		n.OS = osName
		// Only pre-fill Address from agent when not already set by user (dashboard).
		if address != "" && n.Address == "" {
			n.Address = address
		}
		n.Health = "healthy"
		n.Alert = "" // clear alert on reconnect so owner sees fresh state
		n.LastHeartbeat = time.Now()
		_ = s.saveNodes()
		return n
	}
	id := uuid.New().String()
	n := &types.Node{
		ID: id, Hostname: hostname, Address: address, OS: osName,
		Health: "healthy", LastHeartbeat: time.Now(),
		Tags: make(map[string]string), CreatedAt: time.Now(),
	}
	s.nodes[id] = n
	_ = s.saveNodes()
	return n
}

func (s *Store) NodeUpdateMetrics(id string, metrics *types.NodeMetrics) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.nodes[id]
	if n == nil {
		return
	}
	n.CPUUsage = metrics.CPUUsage
	n.RAMUsage = metrics.RAMUsage
	n.RAMTotal = metrics.RAMTotal
	n.DiskUsage = metrics.DiskUsage
	n.DiskTotal = metrics.DiskTotal
	n.NetworkRx = metrics.NetworkRx
	n.NetworkTx = metrics.NetworkTx
	n.CPUUsageServers = metrics.CPUUsageServers
	n.RAMUsageServers = metrics.RAMUsageServers
	n.DebugEnabled = metrics.DebugEnabled
	n.LastHeartbeat = time.Now()
	_ = s.saveNodes()
}

func (s *Store) NodeSetRunningCount(id string, count int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := s.nodes[id]; n != nil {
		n.RunningCount = count
		_ = s.saveNodes()
	}
}

func (s *Store) NodeSetOffline(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := s.nodes[id]; n != nil {
		n.Health = "offline"
		_ = s.saveNodes()
	}
}

// NodePurgeServers deletes all servers assigned to the given node and resets its running count.
// This is used when a node goes offline so stale servers don't linger in state/metrics.
func (s *Store) NodePurgeServers(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nodes[id] == nil {
		return
	}
	for sid, sv := range s.servers {
		if sv.NodeID == id {
			delete(s.servers, sid)
		}
	}
	if n := s.nodes[id]; n != nil {
		n.RunningCount = 0
	}
	_ = s.saveNodes()
	_ = s.saveServers()
}

// NodeSetAlert sets the node's alert message (e.g. "Docker not installed"). Empty string clears the alert.
func (s *Store) NodeSetAlert(id, alert string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := s.nodes[id]; n != nil {
		n.Alert = alert
		_ = s.saveNodes()
	}
}

// NodeDelete removes the node and all servers assigned to it.
func (s *Store) NodeDelete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nodes[id] == nil {
		return
	}
	for sid, sv := range s.servers {
		if sv.NodeID == id {
			delete(s.servers, sid)
		}
	}
	delete(s.nodes, id)
	_ = s.saveNodes()
	_ = s.saveServers()
}

func (s *Store) NodesList() []*types.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*types.Node, 0, len(s.nodes))
	for _, n := range s.nodes {
		list = append(list, n)
	}
	return list
}

// Servers
func (s *Store) ServerByID(id string) *types.Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.servers[id]
}

func (s *Store) ServersList() []*types.Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*types.Server, 0, len(s.servers))
	for _, sv := range s.servers {
		list = append(list, sv)
	}
	return list
}

func (s *Store) ServersByNode(nodeID string) []*types.Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []*types.Server
	for _, sv := range s.servers {
		if sv.NodeID == nodeID {
			list = append(list, sv)
		}
	}
	return list
}

// portRange returns min and max for auto-assigned server ports (from env or defaults).
func portRange() (min, max int) {
	min, max = 25565, 26565
	if v := os.Getenv("PYZANODE_PORT_MIN"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n < 65536 {
			min = n
		}
	}
	if v := os.Getenv("PYZANODE_PORT_MAX"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= min && n < 65536 {
			max = n
		}
	}
	return min, max
}

// pickRandomPort returns a port in [min,max] that is not in used, or 0 if none free.
func pickRandomPort(used map[int]bool, min, max int) int {
	candidates := make([]int, 0, max-min+1)
	for p := min; p <= max; p++ {
		if !used[p] {
			candidates = append(candidates, p)
		}
	}
	if len(candidates) == 0 {
		return 0
	}
	return candidates[rand.Intn(len(candidates))]
}

func (s *Store) ServerCreate(name, presetID, nodeID string, portHint int, group, networkID, serverGroupID, proxyGroupID, shortCode string) (*types.Server, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.presets[presetID] == nil {
		return nil, os.ErrNotExist
	}
	if s.nodes[nodeID] == nil {
		return nil, os.ErrNotExist
	}
	if group == "" && serverGroupID != "" {
		if sg := s.serverGroups[serverGroupID]; sg != nil {
			group = sg.Name
		}
	}
	if group == "" && proxyGroupID != "" {
		if pg := s.proxyGroups[proxyGroupID]; pg != nil {
			group = pg.Name
		}
	}
	if shortCode == "" && group != "" {
		base := serverGroupSlug(group)
		ordinal := 1
		for {
			candidate := base + strconv.Itoa(ordinal)
			clash := false
			for _, sv := range s.servers {
				if sv.ShortCode == candidate {
					clash = true
					break
				}
			}
			if !clash {
				shortCode = candidate
				break
			}
			ordinal++
		}
	}
	used := make(map[int]bool)
	for _, sv := range s.servers {
		if sv.Port > 0 {
			used[sv.Port] = true
		}
	}
	port := portHint
	if port > 0 && port < 65536 {
		if used[port] {
			return nil, fmt.Errorf("port %d already in use", port)
		}
	} else {
		min, max := portRange()
		port = pickRandomPort(used, min, max)
		if port == 0 {
			return nil, os.ErrNotExist // no free port in range
		}
	}
	id := uuid.New().String()
	sv := &types.Server{
		ID: id, Name: name, ShortCode: shortCode, PresetID: presetID, NodeID: nodeID, Port: port, Group: group,
		NetworkID: networkID, ServerGroupID: serverGroupID, ProxyGroupID: proxyGroupID,
		Status: "stopped", CreatedAt: time.Now(),
	}
	s.servers[id] = sv
	_ = s.saveServers()
	return sv, nil
}

// serverGroupSlug returns a lowercase slug for group names (e.g. "Hub" -> "hub", "My Server" -> "myserver").
func serverGroupSlug(group string) string {
	s := strings.ToLower(strings.TrimSpace(group))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if r == ' ' || r == '-' || r == '_' {
			// skip; no separator in slug
		}
	}
	out := b.String()
	if out == "" {
		return "srv"
	}
	return out
}

func (s *Store) ServersByGroup(group string) []*types.Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []*types.Server
	for _, sv := range s.servers {
		if sv.Group == group {
			list = append(list, sv)
		}
	}
	return list
}

func (s *Store) ServerSetGroup(id, group string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sv := s.servers[id]; sv != nil {
		sv.Group = group
		_ = s.saveServers()
		return true
	}
	return false
}

func (s *Store) ServerSetName(id, name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sv := s.servers[id]; sv != nil {
		sv.Name = name
		_ = s.saveServers()
		return true
	}
	return false
}

func (s *Store) ServerSetShortCode(id, shortCode string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sv := s.servers[id]; sv != nil {
		sv.ShortCode = shortCode
		_ = s.saveServers()
		return true
	}
	return false
}

func (s *Store) ServerSetStatus(id, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sv := s.servers[id]; sv != nil {
		sv.Status = status
		if status == "running" {
			now := time.Now()
			sv.StartedAt = &now
			// Default TPS to 20 when a server is reported as running. This gives a
			// more useful dashboard value until we have a real TPS signal.
			if sv.TPS == 0 {
				sv.TPS = 20
			}
		}
		_ = s.saveServers()
	}
}

func (s *Store) ServerUpdateMetrics(id string, m *types.ServerMetrics) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sv := s.servers[id]
	if sv == nil {
		return
	}
	sv.RAMUsage = m.RAMUsage
	sv.CPUUsage = m.CPUUsage
	// PlayerCount and TPS may be derived from higher-level analytics (log parsing).
	// Only trust non-zero values from metrics, so we don't constantly reset counts to 0
	// when the agent doesn't provide them.
	if m.PlayerCount > 0 {
		sv.PlayerCount = m.PlayerCount
	}
	if m.TPS > 0 {
		sv.TPS = m.TPS
	}
	if sv.StartedAt != nil {
		sv.Uptime = time.Since(*sv.StartedAt)
	}
	// LastEmptyAt is maintained based on PlayerCount transitions in analytics (joins/leaves),
	// so avoid overriding it here when metrics don't carry real player data.
	_ = s.saveServers()
}

// ServerUpdateFromPluginMetrics updates per-server metrics from an in-process plugin
// (e.g. Bukkit/Paper or proxy plugin) that has direct access to TPS and player counts.
func (s *Store) ServerUpdateFromPluginMetrics(id string, tps float64, playerCount int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sv := s.servers[id]
	if sv == nil {
		return
	}
	if tps > 0 {
		sv.TPS = tps
	}
	if playerCount >= 0 {
		prev := sv.PlayerCount
		sv.PlayerCount = playerCount
		// When we transition from >0 to 0 players, mark LastEmptyAt; when we go
		// from 0 to >0, clear it.
		if prev > 0 && playerCount == 0 {
			sv.LastEmptyAt = time.Now()
		} else if prev == 0 && playerCount > 0 {
			sv.LastEmptyAt = time.Time{}
		}
	}
	_ = s.saveServers()
}

func (s *Store) ServerDelete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.servers, id)
	_ = s.saveServers()
}

// Presets
func (s *Store) PresetByID(id string) *types.Preset {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.presets[id]
}

func (s *Store) PresetsList() []*types.Preset {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*types.Preset, 0, len(s.presets))
	for _, p := range s.presets {
		list = append(list, p)
	}
	return list
}

// DataDir returns the store's data directory (for packages, etc.).
func (s *Store) DataDir() string {
	return s.dataDir
}

func (s *Store) PresetCreate(p *types.Preset) (*types.Preset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.ID == "" {
		p.ID = uuid.New().String()
	}
	p.CreatedAt = time.Now()
	p.UpdatedAt = p.CreatedAt
	s.presets[p.ID] = p
	_ = s.savePresets()
	return p, nil
}

func (s *Store) PresetUpdate(p *types.Preset) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.presets[p.ID] == nil {
		return os.ErrNotExist
	}
	p.UpdatedAt = time.Now()
	s.presets[p.ID] = p
	_ = s.savePresets()
	return nil
}

func (s *Store) PresetDelete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.presets, id)
	_ = s.savePresets()
}

// Networks
func (s *Store) NetworkByID(id string) *types.Network {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.networks[id]
}

func (s *Store) NetworksList() []*types.Network {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*types.Network, 0, len(s.networks))
	for _, n := range s.networks {
		list = append(list, n)
	}
	return list
}

func (s *Store) NetworkCreate(n *types.Network) (*types.Network, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n.ID == "" {
		n.ID = uuid.New().String()
	}
	n.CreatedAt = time.Now()
	n.UpdatedAt = n.CreatedAt
	if n.Tags == nil {
		n.Tags = make(map[string]string)
	}
	s.networks[n.ID] = n
	_ = s.saveNetworks()
	return n, nil
}

func (s *Store) NetworkUpdate(n *types.Network) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing := s.networks[n.ID]
	if existing == nil {
		return os.ErrNotExist
	}
	n.UpdatedAt = time.Now()
	// Preserve Cloudflare SRV token if client sent masked value
	if n.CloudflareSRV != nil && (n.CloudflareSRV.APIToken == "" || n.CloudflareSRV.APIToken == "***") {
		if existing.CloudflareSRV != nil && existing.CloudflareSRV.APIToken != "" {
			n.CloudflareSRV.APIToken = existing.CloudflareSRV.APIToken
		}
	}
	s.networks[n.ID] = n
	_ = s.saveNetworks()
	return nil
}

func (s *Store) NetworkDelete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.networks, id)
	_ = s.saveNetworks()
}

// ServerGroups
func (s *Store) ServerGroupByID(id string) *types.ServerGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.serverGroups[id]
}

func (s *Store) ServerGroupsList() []*types.ServerGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*types.ServerGroup, 0, len(s.serverGroups))
	for _, g := range s.serverGroups {
		list = append(list, g)
	}
	return list
}

func (s *Store) ServerGroupsByNetwork(networkID string) []*types.ServerGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []*types.ServerGroup
	for _, g := range s.serverGroups {
		if g.NetworkID == networkID {
			list = append(list, g)
		}
	}
	return list
}

func (s *Store) ServerGroupCreate(g *types.ServerGroup) (*types.ServerGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g.ID == "" {
		g.ID = uuid.New().String()
	}
	g.CreatedAt = time.Now()
	g.UpdatedAt = g.CreatedAt
	s.serverGroups[g.ID] = g
	_ = s.saveServerGroups()
	return g, nil
}

func (s *Store) ServerGroupUpdate(g *types.ServerGroup) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.serverGroups[g.ID] == nil {
		return os.ErrNotExist
	}
	g.UpdatedAt = time.Now()
	s.serverGroups[g.ID] = g
	_ = s.saveServerGroups()
	return nil
}

func (s *Store) ServerGroupDelete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.serverGroups, id)
	_ = s.saveServerGroups()
}

// ProxyGroups
func (s *Store) ProxyGroupByID(id string) *types.ProxyGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.proxyGroups[id]
}

func (s *Store) ProxyGroupsList() []*types.ProxyGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*types.ProxyGroup, 0, len(s.proxyGroups))
	for _, g := range s.proxyGroups {
		list = append(list, g)
	}
	return list
}

func (s *Store) ProxyGroupsByNetwork(networkID string) []*types.ProxyGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []*types.ProxyGroup
	for _, g := range s.proxyGroups {
		if g.NetworkID == networkID {
			list = append(list, g)
		}
	}
	return list
}

func (s *Store) ProxyGroupCreate(g *types.ProxyGroup) (*types.ProxyGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g.ID == "" {
		g.ID = uuid.New().String()
	}
	g.CreatedAt = time.Now()
	g.UpdatedAt = g.CreatedAt
	s.proxyGroups[g.ID] = g
	_ = s.saveProxyGroups()
	return g, nil
}

func (s *Store) ProxyGroupUpdate(g *types.ProxyGroup) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.proxyGroups[g.ID] == nil {
		return os.ErrNotExist
	}
	g.UpdatedAt = time.Now()
	s.proxyGroups[g.ID] = g
	_ = s.saveProxyGroups()
	return nil
}

func (s *Store) ProxyGroupDelete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.proxyGroups, id)
	_ = s.saveProxyGroups()
}

func (s *Store) ServersByServerGroup(serverGroupID string) []*types.Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []*types.Server
	for _, sv := range s.servers {
		if sv.ServerGroupID == serverGroupID {
			list = append(list, sv)
		}
	}
	return list
}

func (s *Store) ServersByProxyGroup(proxyGroupID string) []*types.Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []*types.Server
	for _, sv := range s.servers {
		if sv.ProxyGroupID == proxyGroupID {
			list = append(list, sv)
		}
	}
	return list
}

func (s *Store) ServersByNetwork(networkID string) []*types.Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []*types.Server
	for _, sv := range s.servers {
		if sv.NetworkID == networkID {
			list = append(list, sv)
		}
	}
	return list
}

// saveSettings must be called with s.mu held.
func (s *Store) saveSettings() error {
	if s.settings == nil {
		s.settings = &types.Settings{}
	}
	return s.save("settings.json", s.settings)
}

// GetSettings returns a copy of settings.
func (s *Store) GetSettings() types.Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.settings == nil {
		return types.Settings{}
	}
	return *s.settings
}

// SetAutoPortForwardUPnP enables or disables automatic UPnP port forwarding for new servers.
func (s *Store) SetAutoPortForwardUPnP(enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settings == nil {
		s.settings = &types.Settings{}
	}
	s.settings.AutoPortForwardUPnP = enabled
	return s.saveSettings()
}

// SetDebugLogging enables or disables controller debug logging (persisted; caller should also set debuglog.Enabled).
func (s *Store) SetDebugLogging(enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settings == nil {
		s.settings = &types.Settings{}
	}
	s.settings.DebugLogging = enabled
	return s.saveSettings()
}

// UpdateNotificationSettings updates notification-related settings (crash/node + ntfy).
// ntfyPassword: if non-empty, stored; if empty, existing password is left unchanged.
func (s *Store) UpdateNotificationSettings(notifyCrash, notifyNode bool, ntfyURL, ntfyTopic, ntfyToken, ntfyUsername, ntfyPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settings == nil {
		s.settings = &types.Settings{}
	}
	s.settings.NotifyOnCrash = notifyCrash
	s.settings.NotifyOnNodeDisconnect = notifyNode
	s.settings.NtfyURL = ntfyURL
	s.settings.NtfyTopic = ntfyTopic
	s.settings.NtfyToken = ntfyToken
	s.settings.NtfyUsername = ntfyUsername
	if ntfyPassword != "" {
		s.settings.NtfyPassword = ntfyPassword
	}
	return s.saveSettings()
}

// GetCloudflareSRVForSync returns config for SRV sync for the given proxy group (from its network), or nil if disabled/invalid.
func (s *Store) GetCloudflareSRVForSync(proxyGroupID string) *types.CloudflareSRVSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pg := s.proxyGroups[proxyGroupID]
	if pg == nil {
		return nil
	}
	net := s.networks[pg.NetworkID]
	if net == nil || net.CloudflareSRV == nil || !net.CloudflareSRV.Enabled {
		return nil
	}
	cf := net.CloudflareSRV
	if cf.ProxyGroupID != proxyGroupID {
		return nil
	}
	if cf.APIToken == "" || cf.ZoneID == "" || cf.SRVHostname == "" {
		return nil
	}
	cp := *cf
	return &cp
}

func (s *Store) saveAnalyticsEvents() error {
	list := make([]*types.AnalyticsEvent, 0, len(s.analytics))
	for _, ev := range s.analytics {
		list = append(list, ev)
	}
	return s.save("analytics_events.json", list)
}

func (s *Store) savePlayerAnalytics() error {
	m := make(map[string]*types.PlayerAnalytics, len(s.playerStats))
	for k, v := range s.playerStats {
		m[k] = v
	}
	return s.save("player_analytics.json", m)
}

func (s *Store) serverNetworkIDLocked(sv *types.Server) string {
	if sv == nil {
		return ""
	}
	if sv.NetworkID != "" {
		return sv.NetworkID
	}
	if sv.ServerGroupID != "" {
		if g := s.serverGroups[sv.ServerGroupID]; g != nil {
			return g.NetworkID
		}
	}
	if sv.ProxyGroupID != "" {
		if g := s.proxyGroups[sv.ProxyGroupID]; g != nil {
			return g.NetworkID
		}
	}
	return ""
}

func analyticsPlayerKey(networkID, player string) string {
	return networkID + "|" + strings.ToLower(strings.TrimSpace(player))
}

func analyticsIdentityKey(networkID string, ev *types.AnalyticsEvent) string {
	if ev != nil && ev.Metadata != nil {
		if u := strings.TrimSpace(strings.ToLower(ev.Metadata["player_uuid"])); u != "" {
			return networkID + "|uuid:" + u
		}
	}
	player := ""
	if ev != nil {
		player = ev.Player
	}
	return analyticsPlayerKey(networkID, player)
}

func isValidPlayerName(name string) bool {
	name = strings.TrimSpace(name)
	if len(name) < 1 || len(name) > 16 {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			continue
		}
		return false
	}
	return true
}

func mergePlayerStatsRecordsLocked(dst, src *types.PlayerAnalytics) {
	if dst == nil || src == nil {
		return
	}
	dst.Joins += src.Joins
	dst.Leaves += src.Leaves
	dst.Chats += src.Chats
	dst.TotalActiveDurationSec += src.TotalActiveDurationSec
	dst.EstimatedAFKSec += src.EstimatedAFKSec
	if src.LastSeen.After(dst.LastSeen) {
		dst.LastSeen = src.LastSeen
		dst.Online = src.Online
		dst.CurrentSessionStarted = src.CurrentSessionStarted
		dst.CurrentServerID = src.CurrentServerID
		dst.CurrentServer = src.CurrentServer
		dst.CurrentNodeID = src.CurrentNodeID
		dst.CurrentNode = src.CurrentNode
	}
	if dst.Metadata == nil {
		dst.Metadata = map[string]string{}
	}
	for k, v := range src.Metadata {
		if strings.TrimSpace(v) != "" {
			dst.Metadata[k] = v
		}
	}
	if dst.Joins > 0 {
		dst.AverageSessionSec = (dst.TotalActiveDurationSec + dst.EstimatedAFKSec) / int64(dst.Joins)
	}
}

const analyticsAFKIdleThreshold = 30 * time.Second

func (s *Store) updatePlayerStatsLocked(ev *types.AnalyticsEvent) {
	player := strings.TrimSpace(ev.Player)
	if player == "" {
		return
	}
	if !isValidPlayerName(player) {
		// Ignore malformed names parsed from noisy/timestamped log lines.
		return
	}
	key := analyticsIdentityKey(ev.NetworkID, ev)
	ps := s.playerStats[key]
	if ps == nil {
		ps = &types.PlayerAnalytics{
			Player:    player,
			NetworkID: ev.NetworkID,
			Metadata:  map[string]string{},
		}
		s.playerStats[key] = ps
	} else if ps.Metadata == nil {
		// Older records loaded from disk might have nil Metadata; ensure map is initialized
		// before we assign into it below.
		ps.Metadata = map[string]string{}
	}
	// If this event has UUID identity, fold any legacy name-only bucket into it.
	if ev.Metadata != nil {
		if u := strings.TrimSpace(strings.ToLower(ev.Metadata["player_uuid"])); u != "" {
			legacyKey := analyticsPlayerKey(ev.NetworkID, player)
			if legacyKey != key {
				if legacy := s.playerStats[legacyKey]; legacy != nil && legacy != ps {
					mergePlayerStatsRecordsLocked(ps, legacy)
					delete(s.playerStats, legacyKey)
				}
			}
		}
	}
	now := ev.Timestamp
	ps.LastSeen = now
	switch ev.Type {
	case "player_join":
		ps.Joins++
		ps.Online = true
		ps.CurrentSessionStarted = &now
		ps.CurrentServerID = ev.ServerID
		ps.CurrentServer = ev.Server
		ps.CurrentNodeID = ev.NodeID
		ps.CurrentNode = ev.Node
	case "chat":
		ps.Chats++
	case "player_leave":
		ps.Leaves++
		if ps.CurrentSessionStarted != nil {
			dur := now.Sub(*ps.CurrentSessionStarted)
			if dur < 0 {
				dur = 0
			}
			afk := time.Duration(0)
			if started := ps.Metadata["last_activity_at"]; started != "" {
				if t, err := time.Parse(time.RFC3339Nano, started); err == nil {
					inactive := now.Sub(t)
					if inactive > analyticsAFKIdleThreshold {
						afk = inactive - analyticsAFKIdleThreshold
					}
				}
			}
			if afk > dur {
				afk = dur
			}
			active := dur - afk
			ps.TotalActiveDurationSec += int64(active.Seconds())
			ps.EstimatedAFKSec += int64(afk.Seconds())
			if ps.Joins > 0 {
				ps.AverageSessionSec = (ps.TotalActiveDurationSec + ps.EstimatedAFKSec) / int64(ps.Joins)
			}
		}
		ps.Online = false
		ps.CurrentSessionStarted = nil
		ps.CurrentServerID = ""
		ps.CurrentServer = ""
		ps.CurrentNodeID = ""
		ps.CurrentNode = ""
	}
	if ev.Metadata != nil {
		if u := strings.TrimSpace(strings.ToLower(ev.Metadata["player_uuid"])); u != "" {
			ps.Metadata["player_uuid"] = u
		}
	}
	if ev.Type == "player_join" || ev.Type == "chat" {
		ps.Metadata["last_activity_at"] = now.Format(time.RFC3339Nano)
	}
}

// RecordAnalyticsEvent stores a normalized analytics event and updates aggregate player stats.
func (s *Store) RecordAnalyticsEvent(ev *types.AnalyticsEvent) {
	if ev == nil || ev.Type == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ev.ID == "" {
		ev.ID = uuid.New().String()
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	if ev.NetworkID == "" && ev.ServerID != "" {
		if sv := s.servers[ev.ServerID]; sv != nil {
			ev.NetworkID = s.serverNetworkIDLocked(sv)
			if ev.Server == "" {
				ev.Server = sv.Name
			}
			if ev.NodeID == "" {
				ev.NodeID = sv.NodeID
			}
		}
	}
	if ev.NodeID != "" && ev.Node == "" {
		if n := s.nodes[ev.NodeID]; n != nil {
			ev.Node = n.Hostname
		}
	}
	// Update live per-server player counts based on join/leave events so the dashboard
	// can reflect current player numbers even when the agent doesn't provide them.
	if ev.ServerID != "" {
		if sv := s.servers[ev.ServerID]; sv != nil {
			switch ev.Type {
			case "player_join":
				sv.PlayerCount++
				// Server is no longer empty.
				sv.LastEmptyAt = time.Time{}
			case "player_leave":
				if sv.PlayerCount > 0 {
					sv.PlayerCount--
				}
				// When the last player leaves, mark the time so idle shutdown / cleanup
				// can safely treat the server as empty after a grace period.
				if sv.PlayerCount == 0 {
					sv.LastEmptyAt = time.Now()
				}
			}
		}
	}

	s.analytics = append(s.analytics, ev)
	if len(s.analytics) > 20000 {
		s.analytics = s.analytics[len(s.analytics)-20000:]
	}
	s.updatePlayerStatsLocked(ev)
	_ = s.saveAnalyticsEvents()
	_ = s.savePlayerAnalytics()
}

// AnalyticsEvents returns recent events (newest first), optionally filtered by network.
func (s *Store) AnalyticsEvents(limit int, networkID string) []*types.AnalyticsEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 {
		limit = 200
	}
	out := make([]*types.AnalyticsEvent, 0, limit)
	for i := len(s.analytics) - 1; i >= 0 && len(out) < limit; i-- {
		ev := s.analytics[i]
		if networkID != "" && ev.NetworkID != networkID {
			continue
		}
		cp := *ev
		out = append(out, &cp)
	}
	return out
}

// AnalyticsPlayers returns aggregate per-player stats, optionally filtered by network.
func (s *Store) AnalyticsPlayers(networkID string, limit int) []*types.PlayerAnalytics {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*types.PlayerAnalytics, 0, len(s.playerStats))
	for _, p := range s.playerStats {
		if networkID != "" && p.NetworkID != networkID {
			continue
		}
		if !isValidPlayerName(p.Player) {
			continue
		}
		cp := *p
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].TotalActiveDurationSec > out[j].TotalActiveDurationSec
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// AnalyticsSummary returns aggregate counters and top players.
func (s *Store) AnalyticsSummary(networkID string) *types.AnalyticsSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sum := &types.AnalyticsSummary{
		GeneratedAt:  time.Now(),
		NetworkID:    networkID,
		EventsByType: map[string]int{},
	}
	for _, ev := range s.analytics {
		if networkID != "" && ev.NetworkID != networkID {
			continue
		}
		sum.EventsTotal++
		sum.EventsByType[ev.Type]++
	}
	players := make([]types.PlayerAnalytics, 0, len(s.playerStats))
	seenUnique := map[string]bool{}
	for _, p := range s.playerStats {
		if networkID != "" && p.NetworkID != networkID {
			continue
		}
		if !isValidPlayerName(p.Player) {
			continue
		}
		cp := *p
		players = append(players, cp)
		identity := strings.ToLower(strings.TrimSpace(cp.Player))
		if cp.Metadata != nil {
			if u := strings.TrimSpace(strings.ToLower(cp.Metadata["player_uuid"])); u != "" {
				identity = "uuid:" + u
			}
		}
		seenUnique[identity] = true
		sum.TotalJoins += cp.Joins
		sum.TotalLeaves += cp.Leaves
		sum.TotalChats += cp.Chats
		sum.TotalActiveDurationSec += cp.TotalActiveDurationSec
		sum.TotalEstimatedAFKSec += cp.EstimatedAFKSec
	}
	sum.UniquePlayers = len(seenUnique)
	if len(players) > 0 {
		sum.AverageUserActiveTimeSec = sum.TotalActiveDurationSec / int64(len(players))
		sum.AverageEstimatedAFKTimeSec = sum.TotalEstimatedAFKSec / int64(len(players))
	}
	if sum.TotalJoins > 0 {
		sum.AverageSessionDurationSec = (sum.TotalActiveDurationSec + sum.TotalEstimatedAFKSec) / int64(sum.TotalJoins)
	}
	sort.Slice(players, func(i, j int) bool { return players[i].Chats > players[j].Chats })
	for i := 0; i < len(players) && i < 10; i++ {
		sum.TopPlayersByChats = append(sum.TopPlayersByChats, players[i])
	}
	sort.Slice(players, func(i, j int) bool { return players[i].TotalActiveDurationSec > players[j].TotalActiveDurationSec })
	for i := 0; i < len(players) && i < 10; i++ {
		sum.TopPlayersByActiveTime = append(sum.TopPlayersByActiveTime, players[i])
	}
	recent := make([]types.AnalyticsEvent, 0, 100)
	for i := len(s.analytics) - 1; i >= 0 && len(recent) < 100; i-- {
		ev := s.analytics[i]
		if networkID != "" && ev.NetworkID != networkID {
			continue
		}
		recent = append(recent, *ev)
	}
	sum.MostRecentEvents = recent
	return sum
}

// CleanupAnalytics normalizes persisted analytics data, removing malformed player identities
// and duplicate identity buckets. Returns counts of records affected.
func (s *Store) CleanupAnalytics() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()

	removedEvents := 0
	cleanEvents := make([]*types.AnalyticsEvent, 0, len(s.analytics))
	for _, ev := range s.analytics {
		if ev == nil {
			removedEvents++
			continue
		}
		if ev.Type == "player_join" || ev.Type == "player_leave" || ev.Type == "chat" {
			if !isValidPlayerName(ev.Player) {
				removedEvents++
				continue
			}
		}
		cleanEvents = append(cleanEvents, ev)
	}
	s.analytics = cleanEvents

	removedPlayers := 0
	mergedPlayers := 0
	// First pass: merge all records by normalized player name.
	byName := make(map[string]*types.PlayerAnalytics, len(s.playerStats))
	for _, p := range s.playerStats {
		if p == nil {
			removedPlayers++
			continue
		}
		if !isValidPlayerName(p.Player) {
			removedPlayers++
			continue
		}
		nameKey := analyticsPlayerKey(p.NetworkID, p.Player)
		if existing := byName[nameKey]; existing != nil {
			mergedPlayers++
			mergePlayerStatsRecordsLocked(existing, p)
			continue
		}
		cp := *p
		if cp.Metadata == nil {
			cp.Metadata = map[string]string{}
		}
		byName[nameKey] = &cp
	}
	// Second pass: assign canonical keys (uuid when known, otherwise normalized name).
	canonical := make(map[string]*types.PlayerAnalytics, len(byName))
	for _, p := range byName {
		ev := &types.AnalyticsEvent{
			NetworkID: p.NetworkID,
			Player:    p.Player,
			Metadata:  p.Metadata,
		}
		key := analyticsIdentityKey(p.NetworkID, ev)
		if existing := canonical[key]; existing != nil {
			mergedPlayers++
			mergePlayerStatsRecordsLocked(existing, p)
			continue
		}
		canonical[key] = p
	}
	s.playerStats = canonical

	_ = s.saveAnalyticsEvents()
	_ = s.savePlayerAnalytics()
	return map[string]int{
		"events_removed":   removedEvents,
		"players_removed":  removedPlayers,
		"players_merged":   mergedPlayers,
		"events_remaining":  len(s.analytics),
		"players_remaining": len(s.playerStats),
	}
}
