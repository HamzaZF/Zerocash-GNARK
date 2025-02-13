package main

import (
	"bytes"
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

	"github.com/consensys/gnark/constraint"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/rs/zerolog"
)

// -------------------------------
// Logging configuration (readable output)
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

// getNodeColor returns an ANSI color code based on the node's ID.
func getNodeColor(id int) string {
	colors := []string{
		"\033[31m", // red
		"\033[32m", // green
		"\033[33m", // yellow
		"\033[34m", // blue
		"\033[35m", // magenta
		"\033[36m", // cyan
	}
	return colors[id%len(colors)]
}

// -------------------------------
// Node structure and its fields
// -------------------------------
type Node struct {
	ID          int // Unique identifier for the node
	Port        int
	Address     string
	logger      zerolog.Logger
	G           bls12377.G1Affine     // Common G (same for all nodes)
	DHExchanges map[int]*zn.DHParams  // Stores the DH exchange for each peer (key = peer's ID)
	DHHandler   *DiffieHellmanHandler // Dedicated handler for DH exchanges (verifier role)
	//TxHandler      *TransactionHandler   // Dedicated handler for transactions
	TxHandler        TxHandlerInterface
	DHRequestHandler *DHRequestHandler
}

type TxHandlerInterface interface {
	HandleMessage(msg zn.Message, conn net.Conn)
}

// NewNode creates and initializes a node with its ID, port, and the common G.
func NewNode(port int, id int, commonG bls12377.G1Affine, isValidator bool) *Node {
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()

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
	node.DHRequestHandler = NewDHRequestHandler(node)
	//node.TxHandler = NewTransactionHandler(node)
	if isValidator {
		node.TxHandler = NewTransactionValidatorHandler(node)
	} else {
		node.TxHandler = NewTransactionHandler(node)
	}
	return node
}

// -------------------------------
// Node methods
// -------------------------------

// Run starts the node's TCP server and listens for incoming connections.
func (n *Node) Run(wg *sync.WaitGroup) {
	defer wg.Done()
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(n.Port))
	if err != nil {
		n.logger.Error().Err(err).Msg(fmt.Sprintf("%s[Node %d] [TCP Server] Error while listening\033[0m", getNodeColor(n.ID), n.ID))
		return
	}
	n.logger.Info().Msgf("%s[Node %d] [TCP Server] Server started on %s\033[0m", getNodeColor(n.ID), n.ID, n.Address)
	for {
		conn, err := ln.Accept()
		if err != nil {
			n.logger.Error().Err(err).Msg(fmt.Sprintf("%s[Node %d] [TCP Server] Error accepting a connection\033[0m", getNodeColor(n.ID), n.ID))
			continue
		}
		go n.handleConnection(conn)
	}
}

// handleConnection continuously receives gob messages and dispatches them to the appropriate handler.
func (n *Node) handleConnection(conn net.Conn) {
	defer conn.Close()
	for {
		var msg zn.Message
		err := zn.ReceiveMessage(conn, &msg)
		if err != nil {
			if err == io.EOF {
				n.logger.Info().Msg(fmt.Sprintf("%s[Node %d] [Connection] Client closed connection (EOF)\033[0m", getNodeColor(n.ID), n.ID))
			} else {
				n.logger.Error().Err(err).Msg(fmt.Sprintf("%s[Node %d] [Connection] Error receiving message via gob\033[0m", getNodeColor(n.ID), n.ID))
			}
			return
		}
		//n.logger.Info().Msgf("Message reçu : %+v", msg)
		n.logger.Info().Msg(fmt.Sprintf("%s[Node %d] [Message] Message received\033[0m", getNodeColor(n.ID), n.ID))
		switch msg.Type {
		case "DiffieHellman":
			n.DHHandler.HandleMessage(msg, conn)
		case "tx":
			n.TxHandler.HandleMessage(msg, conn)
		case "dh_request":
			n.DHRequestHandler.HandleMessage(msg, conn)
		default:
			zn.RouteMessage(msg, conn)
		}
	}
}

// SendMessage establishes a connection to a target address and sends the message.
func (n *Node) SendMessage(targetAddress string, msg zn.Message) error {
	conn, err := net.Dial("tcp", targetAddress)
	if err != nil {
		n.logger.Error().Err(err).Msgf("%s[Node %d] [SendMessage] Error dialing %s\033[0m", getNodeColor(n.ID), n.ID, targetAddress)
		return err
	}
	defer conn.Close()
	if err := zn.SendMessage(conn, msg); err != nil {
		n.logger.Error().Err(err).Msg(fmt.Sprintf("%s[Node %d] [SendMessage] Error sending message\033[0m", getNodeColor(n.ID), n.ID))
		return err
	}
	n.logger.Info().Msgf("%s[Node %d] [SendMessage] Message sent to %s: %v\033[0m", getNodeColor(n.ID), n.ID, targetAddress, msg)
	return nil
}

// DiffieHellmanKeyExchange executes the key exchange protocol in the initiator role.
// The node initiates the exchange with a peer at targetAddress.
// It generates its ephemeral secret r, computes A = G^r, sends A, waits for B = G^b, computes the shared secret S = B^r,
// then stores the exchange in DHExchanges with the key corresponding to the peer's ID.
func (n *Node) DiffieHellmanKeyExchange(targetAddress string) error {
	var r_bytes [32]byte
	var shared bls12377.G1Affine

	conn, err := net.Dial("tcp", targetAddress)
	if err != nil {
		n.logger.Error().Err(err).Msgf("%s[Node %d] [Diffie-Hellman] Error dialing %s\033[0m", getNodeColor(n.ID), n.ID, targetAddress)
		return err
	}
	defer conn.Close()

	G := n.G

	// Generate the ephemeral secret r and compute A = G^r.
	r, _ := zg.GenerateBls12377_frElement()
	r_bytes = r.Bytes()
	A := *new(bls12377.G1Affine).ScalarMultiplication(&G, new(big.Int).SetBytes(r_bytes[:]))
	// Temporary storage with key -1.
	n.DHExchanges[-1] = &zn.DHParams{
		EphemeralPublic: A,
		Secret:          r_bytes[:],
	}

	// Send "DH_G_r" containing A.
	dhPayload := zn.DHPayload{
		ID:      n.ID,
		SubType: "DH_G_r",
		Value:   A,
	}
	msg := zn.PackMessage("DiffieHellman", dhPayload)
	if err := zn.SendMessage(conn, msg); err != nil {
		n.logger.Error().Err(err).Msg(fmt.Sprintf("%s[Node %d] [Diffie-Hellman] Error sending DH_G_r\033[0m", getNodeColor(n.ID), n.ID))
		return err
	}
	n.logger.Info().Msg(fmt.Sprintf("%s[Node %d] [Diffie-Hellman] DH_G_r sent successfully\033[0m", getNodeColor(n.ID), n.ID))

	// Wait for the response "DH_G_b" from the peer.
	var response zn.Message
	if err := zn.ReceiveMessage(conn, &response); err != nil {
		n.logger.Error().Err(err).Msg(fmt.Sprintf("%s[Node %d] [Diffie-Hellman] Error receiving DH_G_b\033[0m", getNodeColor(n.ID), n.ID))
		return err
	}
	//n.logger.Info().Msgf("Réponse reçue : %+v", response)
	n.logger.Info().Msg(fmt.Sprintf("%s[Node %d] [Diffie-Hellman] Response received\033[0m", getNodeColor(n.ID), n.ID))
	respPayload, ok := response.Payload.(zn.DHPayload)
	if !ok || respPayload.SubType != "DH_G_b" {
		n.logger.Error().Msg(fmt.Sprintf("%s[Node %d] [Diffie-Hellman] Received payload not conforming to DH_G_b\033[0m", getNodeColor(n.ID), n.ID))
		return fmt.Errorf("non conforming payload")
	}
	// Retrieve B sent by the peer (verifier).
	B := respPayload.Value

	// Compute the shared secret S = B^r.
	shared = *new(bls12377.G1Affine).ScalarMultiplication(&B, new(big.Int).SetBytes(r_bytes[:]))

	// Update the map: remove the temporary entry (-1) and use the peer's ID.
	delete(n.DHExchanges, -1)
	n.DHExchanges[respPayload.ID] = &zn.DHParams{
		EphemeralPublic: A,
		PartnerPublic:   B, // Store the received key B (via respPayload.Value)
		Secret:          r_bytes[:],
		SharedSecret:    shared,
	}

	//n.logger.Info().Msgf("Secret partagé calculé: %+v", shared)
	n.logger.Info().Msg(fmt.Sprintf("%s[Node %d] [Diffie-Hellman] Shared secret computed\033[0m", getNodeColor(n.ID), n.ID))
	return nil
}

// SendTransactionDummyImproved sends a dummy transaction for validation.
func (n *Node) SendTransactionDummyImproved(validatorAddress string, targetAddress string, targetID int, globalCCS constraint.ConstraintSystem, globalPK groth16.ProvingKey, globalVK groth16.VerifyingKey) error {

	conn, err := net.Dial("tcp", validatorAddress)
	if err != nil {
		n.logger.Error().Err(err).Msgf("%s[Node %d] [Transaction] Error dialing %s\033[0m", getNodeColor(n.ID), n.ID, validatorAddress)
		return err
	}
	defer conn.Close()

	old1 := zg.Note{
		Value:   zg.NewGamma(12, 5),
		PkOwner: []byte("Alice"),
		Rho:     big.NewInt(1111).Bytes(),
		Rand:    big.NewInt(2222).Bytes(),
	}
	old1.Cm = zg.Committment(old1.Value.Coins, old1.Value.Energy, big.NewInt(1111), big.NewInt(2222))

	old2 := zg.Note{
		Value:   zg.NewGamma(10, 8),
		PkOwner: []byte("Bob"),
		Rho:     big.NewInt(3333).Bytes(),
		Rand:    big.NewInt(4444).Bytes(),
	}
	old2.Cm = zg.Committment(old2.Value.Coins, old2.Value.Energy, big.NewInt(3333), big.NewInt(4444))

	skOld1 := []byte("SK_OLD_1_XX_MIMC_ONLY")
	skOld2 := []byte("SK_OLD_2_XX_MIMC_ONLY")

	// 2 new notes
	new1 := zg.NewGamma(9, 10)
	new2 := zg.NewGamma(13, 3)

	pkNew1 := []byte("pkNew1_XXXXXXXXXXXX")
	pkNew2 := []byte("pkNew2_XXXXXXXXXXXX")

	// 3) Build TxProverInputHighLevel
	inp := zg.TxProverInputHighLevel{
		OldNotes: [2]zg.Note{old1, old2},
		OldSk:    [2][]byte{skOld1, skOld2},
		NewVals:  [2]zg.Gamma{new1, new2},
		NewPk:    [2][]byte{pkNew1, pkNew2},
		EncKey:   n.DHExchanges[targetID].SharedSecret,
		R:        n.DHExchanges[targetID].Secret,
		//B:        b_bytes[:],
		G:   n.G,
		G_b: n.DHExchanges[targetID].PartnerPublic,
		G_r: n.DHExchanges[targetID].EphemeralPublic,
	}

	/*
		// Send "DH_G_r" containing A.
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
	*/

	tx := Transaction(inp, globalCCS, globalPK, conn, n.ID, targetAddress, targetID)

	msg := zn.PackMessage("tx", tx)
	if err := zn.SendMessage(conn, msg); err != nil {
		fmt.Printf("%s[Node %d] [Transaction] Error sending transaction: %v\033[0m\n", getNodeColor(n.ID), n.ID, err)
		return nil
	}

	n.logger.Info().Msg(fmt.Sprintf("%s[Node %d] [Transaction] Transaction sent successfully for validation\033[0m", getNodeColor(n.ID), n.ID))

	// Send the transaction
	//msg := zn.PackMessage("tx", proof)

	/*
		// Send "DH_G_r" containing A.
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
	*/

	//
	return nil
}

func Transaction(inp zg.TxProverInputHighLevel, globalCCS constraint.ConstraintSystem, globalPK groth16.ProvingKey, conn net.Conn, ID int, targetAddress string, targetID int) zn.Tx {
	// 1) snOld[i] = MiMC(skOld[i], RhoOld[i]) off-circuit
	var snOld [2][]byte
	for i := 0; i < 2; i++ {
		sn := zg.CalcSerialMimc(inp.OldSk[i], inp.OldNotes[i].Rho)
		snOld[i] = sn
	}
	// 2) Generate (rhoNew, randNew), cmNew, cNew
	var rhoNew [2]*big.Int
	var randNew [2]*big.Int
	var cmNew [2][]byte
	//var cNew [2][][]byte
	var cNew [2]zg.Note

	for j := 0; j < 2; j++ {
		rhoNew[j] = zg.RandBigInt()
		randNew[j] = zg.RandBigInt()
		cm := zg.Committment(inp.NewVals[j].Coins, inp.NewVals[j].Energy,
			rhoNew[j], randNew[j])
		cmNew[j] = cm
		encVal := zg.BuildEncMimc(inp.EncKey, inp.NewPk[j],
			inp.NewVals[j].Coins, inp.NewVals[j].Energy,
			rhoNew[j], randNew[j], cm)

		// get pk_enc
		pk_enc := encVal[0].Bytes()
		pk_enc_bytes := make([]byte, len(pk_enc))
		copy(pk_enc_bytes, pk_enc[:])
		cNew[j].PkOwner = pk_enc_bytes

		// get coins_enc
		coins_enc := encVal[1].Bytes()
		coins_enc_bytes := make([]byte, len(coins_enc))
		copy(coins_enc_bytes, coins_enc[:])
		cNew[j].Value.Coins = new(big.Int).SetBytes(coins_enc_bytes)

		// get energy_enc
		energy_enc := encVal[2].Bytes()
		energy_enc_bytes := make([]byte, len(energy_enc))
		copy(energy_enc_bytes, energy_enc[:])
		cNew[j].Value.Energy = new(big.Int).SetBytes(energy_enc_bytes)

		// get rho_enc
		rho_enc := encVal[3].Bytes()
		rho_enc_bytes := make([]byte, len(rho_enc))
		copy(rho_enc_bytes, rho_enc[:])
		cNew[j].Rho = rho_enc_bytes

		// get rand_enc
		rand_enc := encVal[4].Bytes()
		rand_enc_bytes := make([]byte, len(rand_enc))
		copy(rand_enc_bytes, rand_enc[:])
		cNew[j].Rand = rand_enc_bytes

		// get cm_enc
		cm_enc := encVal[5].Bytes()
		cm_enc_bytes := make([]byte, len(cm_enc))
		copy(cm_enc_bytes, cm_enc[:])
		cNew[j].Cm = cm_enc_bytes
	}

	// 3) Build InputProver
	var ip zg.InputProver
	// old
	for i := 0; i < 2; i++ {
		ip.OldCoins[i] = inp.OldNotes[i].Value.Coins
		ip.OldEnergy[i] = inp.OldNotes[i].Value.Energy
		ip.CmOld[i] = inp.OldNotes[i].Cm
		ip.SnOld[i] = snOld[i]

		ip.SkOld[i] = new(big.Int).SetBytes(inp.OldSk[i])
		ip.RhoOld[i] = new(big.Int).SetBytes(inp.OldNotes[i].Rho)
		ip.RandOld[i] = new(big.Int).SetBytes(inp.OldNotes[i].Rand)
	}
	// new
	for j := 0; j < 2; j++ {
		ip.NewCoins[j] = inp.NewVals[j].Coins
		ip.NewEnergy[j] = inp.NewVals[j].Energy
		ip.CmNew[j] = cmNew[j]

		// pk

		// allocate with make
		ip.CNew[j] = make([][]byte, 6)
		ip.CNew[j][0] = cNew[j].PkOwner

		// coins
		ip.CNew[j][1] = cNew[j].Value.Coins.Bytes()

		// energy
		ip.CNew[j][2] = cNew[j].Value.Energy.Bytes()

		// rho
		ip.CNew[j][3] = cNew[j].Rho

		// rand
		ip.CNew[j][4] = cNew[j].Rand

		// cm
		ip.CNew[j][5] = cNew[j].Cm

		ip.PkNew[j] = new(big.Int).SetBytes(inp.NewPk[j])
		ip.RhoNew[j] = rhoNew[j]
		ip.RandNew[j] = randNew[j]
	}

	ip.R = inp.R
	//ip.B = inp.B
	ip.G = inp.G
	ip.G_b = inp.G_b
	ip.G_r = inp.G_r
	ip.EncKey = inp.EncKey

	wc, _ := ip.BuildWitness()
	w, _ := frontend.NewWitness(wc, ecc.BW6_761.ScalarField())

	// 4) Generate proof
	_ = time.Now()
	proof, err := groth16.Prove(globalCCS, globalPK, w)
	if err != nil {
		panic(err)
	}

	var buf bytes.Buffer
	proof.WriteTo(&buf)

	txResult := zg.TxResult{
		SnOld: snOld,
		CmNew: cmNew,
		CNew:  [2]zg.Note{cNew[0], cNew[1]},
		Proof: buf.Bytes(),

		RhoNew:  rhoNew,
		RandNew: randNew,
		SkOld:   inp.OldSk,
		RhoOld: [2]*big.Int{
			new(big.Int).SetBytes(inp.OldNotes[0].Rho),
			new(big.Int).SetBytes(inp.OldNotes[1].Rho),
		},
		RandOld: [2]*big.Int{
			new(big.Int).SetBytes(inp.OldNotes[0].Rand),
			new(big.Int).SetBytes(inp.OldNotes[1].Rand),
		},
		PkNew: [2]*big.Int{
			new(big.Int).SetBytes(inp.NewPk[0]),
			new(big.Int).SetBytes(inp.NewPk[1]),
		},
	}

	return zn.Tx{
		TxResult:      txResult,
		Old:           [2]zg.Note{inp.OldNotes[0], inp.OldNotes[1]},
		NewVal:        [2]zg.Gamma{inp.NewVals[0], inp.NewVals[1]},
		ID:            ID,
		TargetAddress: targetAddress,
		TargetID:      targetID,
	}
}

// RelayMessage relays a message (outside the Diffie–Hellman protocol).
func (n *Node) RelayMessage(fromAddress string, targetAddress string, message string) error {
	relayMsg := fmt.Sprintf("Relayed from %s to %s: %s", fromAddress, targetAddress, message)
	return n.SendMessage(targetAddress, zn.PackMessage("relay", relayMsg))
}

// -------------------------------
// Diffie–Hellman Handler (verifier role)
// -------------------------------
type DiffieHellmanHandler struct {
	Node *Node // Pointer to the parent node
}

func NewDiffieHellmanHandler(node *Node) *DiffieHellmanHandler {
	return &DiffieHellmanHandler{
		Node: node,
	}
}

// HandleMessage processes a "DiffieHellman" type message received by the verifier.
// When it receives "DH_G_r", it stores A (the initiator's ephemeral key),
// generates its ephemeral secret b, computes B = G^b, computes the shared secret S = A^b,
// and sends back a "DH_G_b" message containing B.
func (dh *DiffieHellmanHandler) HandleMessage(msg zn.Message, conn net.Conn) {
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()
	remoteAddr := conn.RemoteAddr().String()
	payload, ok := msg.Payload.(zn.DHPayload)
	if !ok {
		fmt.Printf("DiffieHellman Handler (node %d): Non-conforming payload from %s", dh.Node.ID, remoteAddr)
		return
	}

	if payload.SubType == "DH_G_r" {
		// Store A received from the initiator in DHExchanges with key = payload.ID.
		dh.Node.DHExchanges[payload.ID] = &zn.DHParams{
			EphemeralPublic: payload.Value,
		}
		logger.Info().Msg(fmt.Sprintf("%s[Node %d] [Diffie-Hellman] Received DH_G_r from node %d\033[0m", getNodeColor(dh.Node.ID), dh.Node.ID, payload.ID))
		//fmt.Printf("DiffieHellman Handler (node %d): Received DH_G_r from node %d : %+v\n", dh.Node.ID, payload.ID, payload.Value)

		// Generate ephemeral secret b and compute B = G^b.
		b, _ := zg.GenerateBls12377_frElement()
		secret := b.Bytes() // verifier's secret
		B := *new(bls12377.G1Affine).ScalarMultiplication(&dh.Node.G, new(big.Int).SetBytes(secret[:]))
		// Compute the shared secret S = A^b.
		A := dh.Node.DHExchanges[payload.ID].EphemeralPublic
		shared := *new(bls12377.G1Affine).ScalarMultiplication(&A, new(big.Int).SetBytes(secret[:]))
		// Store these values in DHExchanges for this peer.
		dh.Node.DHExchanges[payload.ID] = &zn.DHParams{
			EphemeralPublic: payload.Value, // A received from the initiator
			PartnerPublic:   B,             // B computed by the verifier
			Secret:          secret[:],
			SharedSecret:    shared,
		}

		//fmt.Printf("DiffieHellman Handler (node %d): Shared secret computed: %+v\n", dh.Node.ID, shared)
		logger.Info().Msg(fmt.Sprintf("%s[Node %d] [Diffie-Hellman] Shared secret computed\033[0m", getNodeColor(dh.Node.ID), dh.Node.ID))

		// Send the "DH_G_b" message containing B.
		respPayload := zn.DHPayload{
			ID:      dh.Node.ID,
			SubType: "DH_G_b",
			Value:   B,
		}
		respMsg := zn.PackMessage("DiffieHellman", respPayload)
		if err := zn.SendMessage(conn, respMsg); err != nil {
			logger.Error().Err(err).Msg(fmt.Sprintf("%s[Node %d] [Diffie-Hellman] Error sending DH_G_b to node %d\033[0m", getNodeColor(dh.Node.ID), dh.Node.ID, payload.ID))
			//fmt.Printf("DiffieHellman Handler (node %d): Error sending DH_G_b to node %d: %v\n", dh.Node.ID, payload.ID, err)
		} else {
			logger.Info().Msg(fmt.Sprintf("%s[Node %d] [Diffie-Hellman] DH_G_b sent to node %d\033[0m", getNodeColor(dh.Node.ID), dh.Node.ID, payload.ID))
			//fmt.Printf("DiffieHellman Handler (node %d): DH_G_b sent to node %d\n", dh.Node.ID, payload.ID)
		}
	} else {
		logger.Error().Msg(fmt.Sprintf("%s[Node %d] [Diffie-Hellman] Unknown subtype '%s' from node %d\033[0m", getNodeColor(dh.Node.ID), dh.Node.ID, payload.SubType, payload.ID))
		//fmt.Printf("DiffieHellman Handler (node %d): Unknown subtype '%s' from node %d\n", dh.Node.ID, payload.SubType, payload.ID)
	}
}

// -------------------------------
// Transaction Handler
// -------------------------------

// TransactionHandler manages transaction messages.
type TransactionHandler struct {
	Node *Node // Pointer to the parent node
}

// NewTransactionHandler returns a new TransactionHandler.
func NewTransactionHandler(node *Node) *TransactionHandler {
	return &TransactionHandler{
		Node: node,
	}
}

// HandleMessage processes the "tx" message.
// Here, we assume that the payload is of type zg.TxResult (or an equivalent type based on your implementation).
func (th *TransactionHandler) HandleMessage(msg zn.Message, conn net.Conn) {
	//tx, ok := msg.Payload.(zg.TxResult)
	tx, ok := msg.Payload.(zn.Tx)
	if !ok {
		fmt.Println("TransactionHandler: invalid payload")
		return
	}
	// Process the transaction as needed.
	fmt.Printf("%s[Node %d] [Transaction] Transaction received: %+v\033[0m\n", getNodeColor(th.Node.ID), th.Node.ID, tx)

	ID := tx.ID

	ok = zg.ValidateTx(tx.TxResult,
		tx.Old,
		tx.NewVal,
		th.Node.G,
		th.Node.DHExchanges[ID].PartnerPublic,
		th.Node.DHExchanges[ID].EphemeralPublic)

	fmt.Println("result: ", ok)

	//Get shared secret

	// ok := zg.ValidateTx(tx,
	// 	[2]Note{old1, old2},
	// 	[2]Gamma{new1, new2},
	// 	tx
	// )
}

// -------------------------------
// Transaction Validator Handler
// -------------------------------

type TransactionValidatorHandler struct {
	Node *Node // the validator
}

func NewTransactionValidatorHandler(node *Node) *TransactionValidatorHandler {
	return &TransactionValidatorHandler{Node: node}
}

func (tvh *TransactionValidatorHandler) HandleMessage(msg zn.Message, conn net.Conn) {
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()
	// Extract the transaction (assuming it's of type zn.Tx)
	tx, ok := msg.Payload.(zn.Tx)
	if !ok {
		fmt.Println("TransactionValidatorHandler: invalid payload")
		return
	}
	// Validate the transaction
	// valid := zg.ValidateTx(tx.TxResult, tx.Old, tx.NewVal, tvh.Node.G, tvh.Node.DHExchanges[tx.ID].PartnerPublic, tvh.Node.DHExchanges[tx.ID].EphemeralPublic)

	// Open a connection to the recipient to retrieve its DH parameters
	destConn, err := net.Dial("tcp", tx.TargetAddress)
	if err != nil {
		fmt.Printf("%s[Node %d] [Validator] Error dialing destination %s: %v\033[0m\n", getNodeColor(tvh.Node.ID), tvh.Node.ID, tx.TargetAddress, err)
		return
	}
	defer destConn.Close()

	// Send a DH request
	reqPayload := zn.DHRequestPayload{SenderID: tx.ID}
	reqMsg := zn.PackMessage("dh_request", reqPayload)
	if err := zn.SendMessage(destConn, reqMsg); err != nil {
		fmt.Printf("%s[Node %d] [Validator] Error sending DH request: %v\033[0m\n", getNodeColor(tvh.Node.ID), tvh.Node.ID, err)
		return
	}

	// Wait for the DH response
	var respMsg zn.Message
	if err := zn.ReceiveMessage(destConn, &respMsg); err != nil {
		fmt.Printf("%s[Node %d] [Validator] Error receiving DH response: %v\033[0m\n", getNodeColor(tvh.Node.ID), tvh.Node.ID, err)
		return
	}
	respPayload, ok := respMsg.Payload.(zn.DHResponsePayload)
	if !ok {
		fmt.Println("DH response not conforming")
		return
	}

	// Validate the transaction using the parameters retrieved from the recipient
	valid := zg.ValidateTx(tx.TxResult, tx.Old, tx.NewVal, tvh.Node.G, respPayload.DestPartnerPublic, respPayload.DestEphemeralPublic)

	if valid {
		logger.Info().Msg(fmt.Sprintf("%s[Node %d] [Validator] Transaction validated.\033[0m", getNodeColor(tvh.Node.ID), tvh.Node.ID))
	} else {
		logger.Info().Msg(fmt.Sprintf("%s[Node %d] [Validator] Transaction invalid.\033[0m", getNodeColor(tvh.Node.ID), tvh.Node.ID))
	}
	/*
		if valid {
			fmt.Printf("Transaction validated by validator (node %d).\n", tvh.Node.ID)
			// Send a validation message (if needed)
			//validatedPayload := struct{ Message string }{Message: "Transaction received and intercepted"}
			validatedPayload := zn.Message{
				Type:    "tx_validated",
				Payload: "Transaction received and intercepted",
			}
			validatedMsg := zn.PackMessage("tx_validated", validatedPayload)
			// Here, we could directly reply to the sender, or take another action.
			if err := zn.SendMessage(conn, validatedMsg); err != nil {
				fmt.Printf("Error sending 'tx_validated': %v\n", err)
			}
		} else {
			fmt.Printf("Transaction invalid by validator (node %d).\n", tvh.Node.ID)
		}*/
}

// -------------------------------
// DHRequestHandler
// -------------------------------

type DHRequestHandler struct {
	Node *Node
}

func NewDHRequestHandler(node *Node) *DHRequestHandler {
	return &DHRequestHandler{Node: node}
}

func (drh *DHRequestHandler) HandleMessage(msg zn.Message, conn net.Conn) {
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()
	// Example implementation:
	// Extract the payload of type DHRequestPayload (which you must define)
	req, ok := msg.Payload.(zn.DHRequestPayload)
	if !ok {
		fmt.Println("DHRequestHandler: invalid payload")
		return
	}
	logger.Info().Msg(fmt.Sprintf("%s[Node %d] [DH Request] Received a DH request from sender %d\033[0m", getNodeColor(drh.Node.ID), drh.Node.ID, req.SenderID))

	// Retrieve the DH parameters of the recipient (here assumed to be stored in DHExchanges)
	exchange, exists := drh.Node.DHExchanges[req.SenderID]
	if !exists {
		fmt.Printf("%s[Node %d] [DH Request] No exchange found for sender %d\033[0m\n", getNodeColor(drh.Node.ID), drh.Node.ID, req.SenderID)
		return
	}

	// Build the response with the recipient's info
	resp := zn.DHResponsePayload{
		DestPartnerPublic:   exchange.PartnerPublic,
		DestEphemeralPublic: exchange.EphemeralPublic,
	}
	respMsg := zn.PackMessage("dh_response", resp)
	if err := zn.SendMessage(conn, respMsg); err != nil {
		logger.Info().Msg(fmt.Sprintf("%s[Node %d] [DH Request] Error sending DH response: %v\033[0m", getNodeColor(drh.Node.ID), drh.Node.ID, err))
	} else {
		logger.Info().Msg(fmt.Sprintf("%s[Node %d] [DH Request] DH response sent\033[0m", getNodeColor(drh.Node.ID), drh.Node.ID))
	}
}

// -------------------------------
// main()
// -------------------------------
func main() {
	//zn.RegisterHandler("tx", NewTransactionHandler())

	mainLogger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()

	numNodes := flag.Int("n", 3, "Number of nodes to create")
	basePort := flag.Int("basePort", 9000, "Base port for nodes")
	flag.Parse()

	mainLogger.Info().Msgf("Initializing %d nodes starting from port %d", *numNodes, *basePort)

	// Compute the common G (computed once).
	var commonG bls12377.G1Affine
	{
		gElem, _ := new(fr.Element).SetRandom()
		commonG = *new(bls12377.G1Affine).ScalarMultiplicationBase(gElem.BigInt(new(big.Int)))
	}

	// Create and start the nodes.
	nodes := make([]*Node, *numNodes)
	var wg sync.WaitGroup
	for i := 0; i < *numNodes; i++ {
		port := *basePort + i
		var node *Node
		if i == 1 { // For the first node, pass true
			node = NewNode(port, i, commonG, true)
		} else {
			node = NewNode(port, i, commonG, false)
		}
		nodes[i] = node
		wg.Add(1)
		go node.Run(&wg)
		time.Sleep(100 * time.Millisecond)
	}

	time.Sleep(1 * time.Second)

	//(globalCCS, ) := zg.LoadOrGenerateKeys("default")
	globalCCS, globalPK, globalVK := zg.LoadOrGenerateKeys("default")

	///////////// Diffie–Hellman key exchange //////////////
	// Example: node 0 (initiator) initiates an exchange with node 1 (verifier).
	nodes[0].DiffieHellmanKeyExchange(nodes[2].Address)
	//fmt.Println()
	nodes[0].SendTransactionDummyImproved(nodes[1].Address, nodes[2].Address, nodes[2].ID, globalCCS, globalPK, globalVK)

	mainLogger.Info().Msg("All nodes are operational. Press Ctrl+C to stop.")
	select {}
}
