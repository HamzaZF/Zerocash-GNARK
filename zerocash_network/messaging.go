// messaging.go
package zerocash_network

import (
	"encoding/gob"
	"net"
	zg "zerocash_gnark/zerocash_gnark"
)

const (
	DiffieHellmanMsg = "DiffieHellman"
	TxMsg            = "tx"
	DHRequestMsg     = "dh_request"
	RegisterMsg      = "register" // NEW: Registration message type
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
	gob.Register(zg.TxResult{})
	gob.Register(zg.TxResultDefaultOneCoin{})
	gob.Register(Tx{})
	gob.Register(TxDefaultOneCoinPayload{})
	gob.Register(TxEncapsulated{})
	gob.Register(DHRequestPayload{})
	gob.Register(DHResponsePayload{})
	gob.Register(RegisterPayload{})
	gob.Register(TxRegister{})
	gob.Register(AuctionResult{})
	gob.Register(TxF1Payload{})
	gob.Register(AuctionResultN{})
	gob.Register(TxFNPayload{})
	// Vous pouvez enregistrer d'autres types personnalisés ici si nécessaire.
}
