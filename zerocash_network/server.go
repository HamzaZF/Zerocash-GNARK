// server.go
package zerocash_network

import (
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	zg "zerocash_gnark/zerocash_gnark"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/rs/zerolog"
)

// --- Global verifying key, chargée au démarrage ---
var verifyingKey groth16.VerifyingKey

// ClientManager gère les clients connectés.
type ClientManager struct {
	clients map[net.Conn]bool
	lock    sync.Mutex
}

func NewClientManager() *ClientManager {
	return &ClientManager{clients: make(map[net.Conn]bool)}
}

func (cm *ClientManager) AddClient(conn net.Conn) {
	cm.lock.Lock()
	defer cm.lock.Unlock()
	cm.clients[conn] = true
	fmt.Printf("[INFO] Nouveau client connecté: %s\n", conn.RemoteAddr())
}

func (cm *ClientManager) RemoveClient(conn net.Conn) {
	cm.lock.Lock()
	defer cm.lock.Unlock()
	delete(cm.clients, conn)
	fmt.Printf("[INFO] Client déconnecté: %s\n", conn.RemoteAddr())
}

func (cm *ClientManager) Broadcast(msg Message) {
	cm.lock.Lock()
	defer cm.lock.Unlock()
	for conn := range cm.clients {
		go func(c net.Conn) {
			if err := SendMessage(c, msg); err != nil {
				fmt.Printf("[ERREUR] Erreur lors de l'envoi à %s: %v\n", c.RemoteAddr(), err)
			}
		}(conn)
	}
}

var manager = NewClientManager()

// preview retourne les n premiers éléments d'un tableau de bytes (ou l'ensemble si moins de n éléments).
func preview(data []byte, n int) []byte {
	if len(data) < n {
		return data
	}
	return data[:n]
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	manager.AddClient(conn)
	defer manager.RemoveClient(conn)

	//G1
	var G1 bls12377.G1Affine
	var G_r bls12377.G1Affine
	var G_r_b bls12377.G1Affine

	for {
		var msg Message
		if err := ReceiveMessage(conn, &msg); err != nil {
			if err.Error() == "EOF" {
				fmt.Printf("[INFO] Connexion fermée par %s\n", conn.RemoteAddr())
			} else {
				fmt.Printf("[ERREUR] Erreur lors de la lecture de %s: %v\n", conn.RemoteAddr(), err)
			}
			return
		}

		switch msg.Type {
		case "proof":
			// // On tente d'extraire le payload en tant que ProofPackage.
			// proofPkg, ok := msg.Payload.(ProofPackage)
			// if ok {
			// 	fmt.Printf("[REÇU] Preuve reçue de %s:\n", conn.RemoteAddr())
			// 	fmt.Printf("       Proof: []byte (len=%d, preview=%v)\n", len(proofPkg.Proof), preview(proofPkg.Proof, 10))
			// 	fmt.Printf("       PublicInputs: %+v\n", proofPkg.PublicInputs)

			// 	// Vérification de la preuve
			// 	proofBuff := new(bytes.Buffer)
			// 	proofBuff.Write(proofPkg.Proof)
			// 	proof := groth16.NewProof(ecc.BW6_761)
			// 	_, err := proof.ReadFrom(proofBuff)
			// 	if err != nil {
			// 		fmt.Printf("[ERREUR] Lecture de la preuve: %v\n", err)
			// 		break
			// 	}

			// 	assignment := new(CircuitDummy)
			// 	// Ici, on suppose que l'input public (Y) est stocké dans publicInputs.
			// 	assignment.Y = new(big.Int).SetBytes(proofPkg.PublicInputs.Y[:])
			// 	witness, err := frontend.NewWitness(assignment, ecc.BW6_761.ScalarField(), frontend.PublicOnly())
			// 	if err != nil {
			// 		fmt.Printf("[ERREUR] Création du witness: %v\n", err)
			// 		break
			// 	}
			// 	publicWitness, _ := witness.Public()

			// 	err = groth16.Verify(proof, verifyingKey, publicWitness)
			// 	if err != nil {
			// 		fmt.Printf("[ERREUR] Vérification échouée: %v\n", err)
			// 	} else {
			// 		fmt.Printf("[INFO] Vérification réussie pour le client %s\n", conn.RemoteAddr())
			// 	}
			// } else {
			// 	fmt.Printf("[ERREUR] Le payload pour le type proof n'est pas de type ProofPackage\n")
			// }
		case "DiffieHellman":
			point, ok := msg.Payload.(Point)
			if ok {
				if point.Type == "DH_G1" {
					G1 = point.Payload
					fmt.Printf("[REÇU] G1 reçu de %s:\n", conn.RemoteAddr())
					fmt.Printf("       G1: %+v\n", G1)
				} else if point.Type == "DH_G_r" {
					G_r = point.Payload
					fmt.Printf("[REÇU] G_r reçu de %s:\n", conn.RemoteAddr())
					fmt.Printf("       G_r: %+v\n", G_r)

					//compute G_b

					b, _ := zg.GenerateBls12377_frElement()
					b_bytes := b.Bytes()

					G_b := new(bls12377.G1Affine).ScalarMultiplication(&G1, new(big.Int).SetBytes(b_bytes[:]))

					//send G_b
					response := Message{
						Type: "DiffieHellman",
						Payload: Point{
							Type:    "DH_G_b",
							Payload: *G_b,
						},
					}
					if err := SendMessage(conn, response); err != nil {
						fmt.Printf("[ERREUR] Erreur lors de l'envoi de la réponse à %s: %v\n", conn.RemoteAddr(), err)
					}

					//compute G_r_b
					G_r_b = *new(bls12377.G1Affine).ScalarMultiplication(&G_r, new(big.Int).SetBytes(b_bytes[:]))

					fmt.Println("G_r_b = ", G_r_b)

				} else {
					fmt.Printf("[ERREUR] Le type de point n'est pas reconnu\n")
				}
			} else {
				fmt.Printf("[ERREUR] Le payload n'est pas reconnu\n")
			}
		default:
			fmt.Printf("[REÇU] De %s : Type=%s, Payload: %+v\n", conn.RemoteAddr(), msg.Type, msg.Payload)
		}

		// Renvoyer un accusé de réception générique.
		// response := Message{
		// 	Type:    "ack",
		// 	Payload: "Message bien reçu",
		// }
		// if err := SendMessage(conn, response); err != nil {
		// 	fmt.Printf("[ERREUR] Erreur lors de l'envoi de la réponse à %s: %v\n", conn.RemoteAddr(), err)
		// }
	}
}

func ServerMain(port string) {
	// Configuration du logger pour le serveur.
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()
	logger.Info().Msg("Démarrage du serveur...")

	// On écoute sur le port spécifié (on préfixe par ":" si nécessaire)
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Println("Erreur lors de l'écoute :", err)
		os.Exit(1)
	}
	fmt.Printf("Serveur démarré sur le port %s\n", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Erreur lors de l'acceptation :", err)
			continue
		}
		go handleConnection(conn)
	}
}
