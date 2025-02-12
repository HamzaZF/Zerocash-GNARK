// messaging.go
package zerocash_network

import (
	"encoding/gob"
	"net"
)

func SendMessage(conn net.Conn, data interface{}) error {
	encoder := gob.NewEncoder(conn)
	return encoder.Encode(data)
}

func ReceiveMessage(conn net.Conn, out interface{}) error {
	decoder := gob.NewDecoder(conn)
	return decoder.Decode(out)
}

// Enregistrez ici, si nécessaire, vos types personnalisés afin que gob sache les encoder.
func init() {
	//gob.Register(ProofPackage{})
	gob.Register(Message{})
	gob.Register(Point{})
	gob.Register(DHPayload{})
	gob.Register(DHParams{})
	// Vous pouvez enregistrer d'autres types personnalisés ici si nécessaire.
}
