package main

import (
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	zg "zerocash_gnark/zerocash_gnark"
	zn "zerocash_gnark/zerocash_network"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/rs/zerolog"
)

// -------------------------------
// Configuration du logging (sortie lisible)
// -------------------------------
var consoleWriter = zerolog.ConsoleWriter{
	Out:        os.Stdout,
	TimeFormat: time.RFC1123,
	FormatLevel: func(i interface{}) string {
		return fmt.Sprintf("[%-6s]", i)
	},
	FormatMessage: func(i interface{}) string {
		return fmt.Sprintf(" %s", i)
	},
	FormatFieldName: func(i interface{}) string {
		return fmt.Sprintf("%s:", i)
	},
	FormatFieldValue: func(i interface{}) string {
		return fmt.Sprintf("%s", i)
	},
}

// -------------------------------
// Structure Node et ses champs
// -------------------------------
type Node struct {
	ID          int // Identifiant unique du nœud
	Port        int
	Address     string
	logger      zerolog.Logger
	G           bls12377.G1Affine     // Common G (identique pour tous)
	DHExchanges map[int]*zn.DHParams  // Stocke l'échange DH pour chaque pair (clé = ID du pair)
	DHHandler   *DiffieHellmanHandler // Handler dédié pour les échanges DH (rôle vérifieur)
}

// NewNode crée et initialise un nœud avec son ID, son port et le common G.
func NewNode(port int, id int, commonG bls12377.G1Affine) *Node {
	logger := zerolog.New(consoleWriter).With().
		Timestamp().
		Str("node", fmt.Sprintf(":%d", port)).
		Logger()

	address := "127.0.0.1:" + strconv.Itoa(port)
	node := &Node{
		ID:          id,
		Port:        port,
		Address:     address,
		logger:      logger,
		G:           commonG,
		DHExchanges: make(map[int]*zn.DHParams),
	}
	node.DHHandler = NewDiffieHellmanHandler(node)
	return node
}

// -------------------------------
// Méthodes du Node
// -------------------------------

// Run démarre le serveur TCP du nœud et attend les connexions entrantes.
func (n *Node) Run(wg *sync.WaitGroup) {
	defer wg.Done()
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(n.Port))
	if err != nil {
		n.logger.Error().Err(err).Msg("Erreur lors de l'écoute")
		return
	}
	n.logger.Info().Msgf("Serveur démarré sur %s", n.Address)
	for {
		conn, err := ln.Accept()
		if err != nil {
			n.logger.Error().Err(err).Msg("Erreur lors de l'acceptation d'une connexion")
			continue
		}
		go n.handleConnection(conn)
	}
}

// handleConnection reçoit des messages via gob en boucle et les transmet au handler approprié.
func (n *Node) handleConnection(conn net.Conn) {
	defer conn.Close()
	for {
		var msg zn.Message
		err := zn.ReceiveMessage(conn, &msg)
		if err != nil {
			if err == io.EOF {
				n.logger.Info().Msg("Connexion fermée par le client (EOF)")
			} else {
				n.logger.Error().Err(err).Msg("Erreur lors de la réception du message via gob")
			}
			return
		}
		n.logger.Info().Msgf("Message reçu : %+v", msg)
		if msg.Type == "DiffieHellman" {
			n.DHHandler.HandleMessage(msg, conn)
		} else {
			zn.RouteMessage(msg, conn)
		}
	}
}

// SendMessage établit une connexion vers une adresse cible et envoie le message.
func (n *Node) SendMessage(targetAddress string, msg zn.Message) error {
	conn, err := net.Dial("tcp", targetAddress)
	if err != nil {
		n.logger.Error().Err(err).Msgf("Erreur lors du dial vers %s", targetAddress)
		return err
	}
	defer conn.Close()
	if err := zn.SendMessage(conn, msg); err != nil {
		n.logger.Error().Err(err).Msg("Erreur lors de l'envoi du message")
		return err
	}
	n.logger.Info().Msgf("Message envoyé à %s : %v", targetAddress, msg)
	return nil
}

// DiffieHellmanKeyExchange exécute le protocole d'échange de clés pour le rôle d'initiateur.
// Le nœud initie l'échange avec un pair situé à targetAddress.
// Il génère son secret r, calcule A = G^r, envoie A, attend B = G^b, calcule le secret partagé S = B^r,
// puis stocke l'échange dans DHExchanges sous la clé correspondant à l'ID du pair.
func (n *Node) DiffieHellmanKeyExchange(targetAddress string) error {
	var r_bytes [32]byte
	var shared bls12377.G1Affine

	conn, err := net.Dial("tcp", targetAddress)
	if err != nil {
		n.logger.Error().Err(err).Msgf("Erreur lors du dial vers %s", targetAddress)
		return err
	}
	defer conn.Close()

	G := n.G

	// Générer le secret éphémère r et calculer A = G^r.
	r, _ := zg.GenerateBls12377_frElement()
	r_bytes = r.Bytes()
	A := *new(bls12377.G1Affine).ScalarMultiplication(&G, new(big.Int).SetBytes(r_bytes[:]))
	// Stockage temporaire sous clé -1.
	n.DHExchanges[-1] = &zn.DHParams{
		EphemeralPublic: A,
		Secret:          r_bytes[:],
	}

	// Envoyer "DH_G_r" contenant A.
	dhPayload := zn.DHPayload{
		ID:      n.ID,
		SubType: "DH_G_r",
		Value:   A,
	}
	msg := zn.PackMessage("DiffieHellman", dhPayload)
	if err := zn.SendMessage(conn, msg); err != nil {
		n.logger.Error().Err(err).Msg("Erreur lors de l'envoi de DH_G_r")
		return err
	}
	n.logger.Info().Msg("DH_G_r envoyé avec succès.")

	// Attendre la réponse "DH_G_b" du pair.
	var response zn.Message
	if err := zn.ReceiveMessage(conn, &response); err != nil {
		n.logger.Error().Err(err).Msg("Erreur lors de la réception de DH_G_b")
		return err
	}
	n.logger.Info().Msgf("Réponse reçue : %+v", response)
	respPayload, ok := response.Payload.(zn.DHPayload)
	if !ok || respPayload.SubType != "DH_G_b" {
		n.logger.Error().Msg("Payload reçu non conforme pour DH_G_b")
		return fmt.Errorf("payload non conforme")
	}
	// Récupérer B envoyé par le pair (vérifieur).
	B := respPayload.Value

	// Calculer le secret partagé S = B^r.
	shared = *new(bls12377.G1Affine).ScalarMultiplication(&B, new(big.Int).SetBytes(r_bytes[:]))

	// Mettre à jour la map : supprimer l'entrée temporaire (-1) et utiliser l'ID du pair.
	delete(n.DHExchanges, -1)
	n.DHExchanges[respPayload.ID] = &zn.DHParams{
		EphemeralPublic: A,
		Secret:          r_bytes[:],
		SharedSecret:    shared,
	}
	n.logger.Info().Msgf("Secret partagé calculé: %+v", shared)
	return nil
}

// RelayMessage permet de relayer un message (hors protocole Diffie–Hellman).
func (n *Node) RelayMessage(fromAddress string, targetAddress string, message string) error {
	relayMsg := fmt.Sprintf("Relayed from %s to %s: %s", fromAddress, targetAddress, message)
	return n.SendMessage(targetAddress, zn.PackMessage("relay", relayMsg))
}

// -------------------------------
// Handler Diffie–Hellman (rôle de vérifieur)
// -------------------------------
type DiffieHellmanHandler struct {
	Node *Node // Pointeur vers le nœud parent
}

func NewDiffieHellmanHandler(node *Node) *DiffieHellmanHandler {
	return &DiffieHellmanHandler{
		Node: node,
	}
}

// HandleMessage traite un message de type "DiffieHellman" reçu par le vérifieur.
// Lorsqu'il reçoit "DH_G_r", il stocke A (la clé éphémère de l'initiateur),
// génère son secret b, calcule B = G^b, calcule le secret partagé S = A^b,
// et renvoie un message "DH_G_b" contenant B.
func (dh *DiffieHellmanHandler) HandleMessage(msg zn.Message, conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	payload, ok := msg.Payload.(zn.DHPayload)
	if !ok {
		fmt.Printf("Handler DiffieHellman (node %d): Payload non conforme depuis %s\n", dh.Node.ID, remoteAddr)
		return
	}

	if payload.SubType == "DH_G_r" {
		// Stocker A reçu de l'initiateur dans DHExchanges sous la clé = payload.ID.
		dh.Node.DHExchanges[payload.ID] = &zn.DHParams{
			EphemeralPublic: payload.Value,
		}
		fmt.Printf("Handler DiffieHellman (node %d): Reçu DH_G_r de node %d : %+v\n", dh.Node.ID, payload.ID, payload.Value)

		// Générer le secret éphémère b et calculer B = G^b.
		b, _ := zg.GenerateBls12377_frElement()
		secret := b.Bytes() // secret du vérifieur
		B := *new(bls12377.G1Affine).ScalarMultiplication(&dh.Node.G, new(big.Int).SetBytes(secret[:]))
		// Calculer le secret partagé S = A^b.
		A := dh.Node.DHExchanges[payload.ID].EphemeralPublic
		shared := *new(bls12377.G1Affine).ScalarMultiplication(&A, new(big.Int).SetBytes(secret[:]))
		// Stocker ces valeurs dans DHExchanges pour ce pair.
		dh.Node.DHExchanges[payload.ID].Secret = secret[:]
		dh.Node.DHExchanges[payload.ID].SharedSecret = shared
		fmt.Printf("Handler DiffieHellman (node %d): Secret partagé calculé: %+v\n", dh.Node.ID, shared)

		// Envoyer le message "DH_G_b" contenant B.
		respPayload := zn.DHPayload{
			ID:      dh.Node.ID,
			SubType: "DH_G_b",
			Value:   B,
		}
		respMsg := zn.PackMessage("DiffieHellman", respPayload)
		if err := zn.SendMessage(conn, respMsg); err != nil {
			fmt.Printf("Handler DiffieHellman (node %d): Erreur lors de l'envoi de DH_G_b vers node %d: %v\n", dh.Node.ID, payload.ID, err)
		} else {
			fmt.Printf("Handler DiffieHellman (node %d): DH_G_b envoyé vers node %d\n", dh.Node.ID, payload.ID)
		}
	} else {
		fmt.Printf("Handler DiffieHellman (node %d): Sous-type inconnu '%s' depuis node %d\n", dh.Node.ID, payload.SubType, payload.ID)
	}
}

// -------------------------------
// Fonction printHelp (inchangée)
// -------------------------------
func printHelp() {
	fmt.Println("Usage: main <command>")
	fmt.Println("Available commands:")
	fmt.Println("  server")
	fmt.Println("  client")
	fmt.Println("  help")
}

// -------------------------------
// main()
// -------------------------------
func main() {
	mainLogger := zerolog.New(consoleWriter).With().Timestamp().Logger()

	numNodes := flag.Int("n", 3, "Nombre de nœuds à créer")
	basePort := flag.Int("basePort", 9000, "Port de base pour les nœuds")
	flag.Parse()

	mainLogger.Info().Msgf("Initialisation de %d nœuds à partir du port %d", *numNodes, *basePort)

	// Calcul du common G (calculé une seule fois).
	var commonG bls12377.G1Affine
	{
		gElem, _ := new(fr.Element).SetRandom()
		commonG = *new(bls12377.G1Affine).ScalarMultiplicationBase(gElem.BigInt(new(big.Int)))
	}

	// Création et démarrage des nœuds.
	nodes := make([]*Node, *numNodes)
	var wg sync.WaitGroup
	for i := 0; i < *numNodes; i++ {
		port := *basePort + i
		node := NewNode(port, i, commonG)
		nodes[i] = node
		wg.Add(1)
		go node.Run(&wg)
		time.Sleep(100 * time.Millisecond)
	}

	time.Sleep(1 * time.Second)

	///////////// Diffie–Hellman key exchange //////////////
	// Exemple : le nœud 0 (initiateur) initie un échange avec le nœud 1 (vérifieur).
	nodes[0].DiffieHellmanKeyExchange(nodes[1].Address)

	mainLogger.Info().Msg("Tous les nœuds sont opérationnels. Appuyez sur Ctrl+C pour arrêter.")
	select {}
}
