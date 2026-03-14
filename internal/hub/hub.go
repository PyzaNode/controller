package hub

import (
	"encoding/json"
	"log"
	"sync"

	"github.com/gorilla/websocket"
)

// AgentConn represents a connected agent (node).
type AgentConn struct {
	NodeID string
	Send   chan []byte
	conn   *websocket.Conn
}

type Hub struct {
	mu     sync.RWMutex
	agents map[string]*AgentConn // nodeID -> conn
}

func New() *Hub {
	return &Hub{agents: make(map[string]*AgentConn)}
}

func (h *Hub) Register(nodeID string, conn *websocket.Conn) *AgentConn {
	h.mu.Lock()
	defer h.mu.Unlock()
	if old := h.agents[nodeID]; old != nil {
		close(old.Send)
	}
	ac := &AgentConn{NodeID: nodeID, Send: make(chan []byte, 64), conn: conn}
	h.agents[nodeID] = ac
	return ac
}

func (h *Hub) Unregister(nodeID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ac := h.agents[nodeID]; ac != nil {
		close(ac.Send)
		delete(h.agents, nodeID)
	}
}

func (h *Hub) SendToNode(nodeID string, msg interface{}) bool {
	h.mu.RLock()
	ac := h.agents[nodeID]
	h.mu.RUnlock()
	if ac == nil {
		return false
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return false
	}
	select {
	case ac.Send <- data:
		return true
	default:
		return false
	}
}

// SendCommand sends a command to the agent on the given node.
func (h *Hub) SendCommand(nodeID string, cmd string, payload interface{}) bool {
	return h.SendToNode(nodeID, map[string]interface{}{"type": cmd, "payload": payload})
}

// NodeIDs returns a copy of connected node IDs (for periodic broadcast).
func (h *Hub) NodeIDs() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	ids := make([]string, 0, len(h.agents))
	for id := range h.agents {
		ids = append(ids, id)
	}
	return ids
}

func (h *Hub) RunAgent(ac *AgentConn) {
	defer func() {
		h.Unregister(ac.NodeID)
		ac.conn.Close()
	}()
	for data := range ac.Send {
		if err := ac.conn.WriteMessage(websocket.TextMessage, data); err != nil {
			log.Printf("hub: write to node %s: %v", ac.NodeID, err)
			return
		}
	}
}
