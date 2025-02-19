// common.go
package zerocash_network

import (
	"net"
	zg "zerocash_gnark/zerocash_gnark"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
)

type Message struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

type Point struct {
	Type    string            `json:"type"`
	Payload bls12377.G1Affine `json:"payload"`
}

// -------------------------------
// Type DHPayload pour l'échange Diffie–Hellman
// -------------------------------
type DHPayload struct {
	ID      int               `json:"id"`      // Identifiant de l'émetteur
	SubType string            `json:"subtype"` // "DH_G_r" ou "DH_G_b"
	Value   bls12377.G1Affine `json:"value"`   // La valeur éphémère (G^r ou G^b)
}

// -------------------------------
// Structure DHParams : paramètres d'échange pour un pair
// -------------------------------
type DHParams struct {
	EphemeralPublic bls12377.G1Affine // La clé éphémère de ce nœud (A pour l'initiateur)
	PartnerPublic   bls12377.G1Affine // La clé éphémère du pair (B pour l'initiateur, ou A pour le vérifieur)
	Secret          []byte            // Le secret éphémère (r pour l'initiateur, b pour le vérifieur)
	SharedSecret    bls12377.G1Affine // Le secret partagé S = (G^r)^b = (G^b)^r
}

type Tx struct {
	TxResult      zg.TxResult
	Old           [2]zg.Note
	NewVal        [2]zg.Gamma
	ID            int
	TargetAddress string
	TargetID      int
}

type TxEncapsulated struct { ///MAJ MAIN GO; add serialization list, ...
	Kind    int
	Payload interface{}
}

type TxRegisterNew struct {
	TxIn      TxEncapsulated
	CmIn      []byte
	PiReg     []byte
	Ip        zg.InputProverRegister
	AuxCipher [5][]byte
}

type TxRegister struct {
	TxIn      TxEncapsulated
	CmIn      []byte
	PiReg     []byte
	PubW      []byte
	Ip        zg.InputProverRegister
	AuxCipher [5][]byte
}

// type TxRegister struct {
// 	TxIn      TxEncapsulated,

type TxDefaultOneCoinPayload struct {
	TxResult      zg.TxResultDefaultOneCoin
	Old           zg.Note
	NewVal        zg.Gamma
	ID            int
	TargetAddress string
	TargetID      int
	PublicWitness []byte
}

type DHRequestPayload struct {
	SenderID int // ID de l'émetteur de la transaction
}
type DHResponsePayload struct {
	DestPartnerPublic   bls12377.G1Affine // La clé publique éphémère du destinataire (B)
	DestEphemeralPublic bls12377.G1Affine // La clé éphémère du destinataire (par exemple, A' ou autre)
}

type RegisterPayload struct {
	AuxCipher []byte                  // ℂ^{Aux}: the auxiliary ciphertext
	TxIn      TxDefaultOneCoinPayload // The "in" transaction (tx^{in})
	PiReg     []byte                  // The registration proof π_reg
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
