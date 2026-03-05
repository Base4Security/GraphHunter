package ws

import (
	"log"

	"github.com/gofiber/contrib/websocket"
)

// HandleConnection manages a single WebSocket client lifecycle.
// Reads messages (for keep-alive/ping), and unregisters on close.
func HandleConnection(hub *Hub, c *websocket.Conn) {
	hub.Register(c)
	defer hub.Unregister(c)

	for {
		// Read loop — we don't expect client messages, but need to consume
		// to detect disconnects.
		_, _, err := c.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("ws: client error: %v", err)
			}
			break
		}
	}
}
