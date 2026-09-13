package api

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

type Hub struct {
	mu      sync.RWMutex
	clients map[*websocket.Conn]bool
	broadcast chan []byte
	upgrader websocket.Upgrader
}

func NewHub() *Hub {
	return &Hub{
		clients:   make(map[*websocket.Conn]bool),
		broadcast: make(chan []byte, 256),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

func (h *Hub) Run() {
	for msg := range h.broadcast {
		h.mu.RLock()
		for client := range h.clients {
			err := client.WriteMessage(websocket.TextMessage, msg)
			if err != nil {
				log.Printf("websocket write error: %v", err)
				client.Close()
				delete(h.clients, client)
			}
		}
		h.mu.RUnlock()
	}
}

func (h *Hub) Broadcast(eventType string, data interface{}) {
	payload := map[string]interface{}{
		"type": eventType,
		"data": data,
	}
	msg, err := json.Marshal(payload)
	if err != nil {
		log.Printf("marshal event: %v", err)
		return
	}
	select {
	case h.broadcast <- msg:
	default:
		log.Printf("broadcast channel full, dropping event: %s", eventType)
	}
}

func (h *Hub) HandleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("websocket upgrade: %v", err)
		return
	}
	h.mu.Lock()
	h.clients[conn] = true
	h.mu.Unlock()

	// Send initial state
	// (handled by server sending current state on connect)

	// Keep-alive loop
	go func() {
		defer func() {
			h.mu.Lock()
			delete(h.clients, conn)
			h.mu.Unlock()
			conn.Close()
		}()
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
		}
	}()
}

func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}
