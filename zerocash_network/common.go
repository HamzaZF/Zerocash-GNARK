// common.go
package zerocash_network

import "net"

type Message struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

type Handler interface {
	HandleMessage(msg Message, conn net.Conn)
}

var handlers = make(map[string]Handler)

func RegisterHandler(messageType string, handler Handler) {
	handlers[messageType] = handler
}

func RouteMessage(msg Message, conn net.Conn) {
	if handler, ok := handlers[msg.Type]; ok {
		handler.HandleMessage(msg, conn)
	} else {
		println("Aucun handler pour le type :", msg.Type)
	}
}

func PackMessage(meta string, payload interface{}) Message {
	return Message{
		Type:    meta,
		Payload: payload,
	}
}
