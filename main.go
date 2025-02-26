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

	mimcNative "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"

	"github.com/consensys/gnark/constraint"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"

	//"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	bls12377_fp "github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
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
	TxHandler TxHandlerInterface
	//TxDefaultOneCoinHandler *TransactionDefaultOneCoinHandler
	DHRequestHandler *DHRequestHandler
	RegisterHandler  *RegisterHandler
	AuctionHandler   *AuctionHandler
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
	node.RegisterHandler = NewRegisterHandler(node)
	node.AuctionHandler = NewAuctionHandler(node)
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
		//case "txDefaultOneCoin":
		//	n.TxDefaultOneCoinHandler.HandleMessage(msg, conn)
		case "dh_request":
			n.DHRequestHandler.HandleMessage(msg, conn)
		case "register":
			n.RegisterHandler.HandleMessage(msg, conn)
		case "auction":
			n.AuctionHandler.HandleMessage(msg, conn)
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

	//compute PkOwner_0
	sk_old_0, _ := zg.GenerateBls12377_frElement()
	sk_old_0_bytes := sk_old_0.Bytes()
	h := mimcNative.NewMiMC()
	h.Write(sk_old_0_bytes[:])
	PkOwner_0 := h.Sum(nil)

	old1 := zg.Note{
		Value:   zg.NewGamma(12, 5),
		PkOwner: PkOwner_0,
		Rho:     big.NewInt(1111).Bytes(),
		Rand:    big.NewInt(2222).Bytes(),
	}
	old1.Cm = zg.Committment(old1.Value.Coins, old1.Value.Energy, big.NewInt(1111), big.NewInt(2222))

	//compute PkOwner_1
	sk_old_1, _ := zg.GenerateBls12377_frElement()
	sk_old_1_bytes := sk_old_1.Bytes()
	h = mimcNative.NewMiMC()
	h.Write(sk_old_1_bytes[:])
	PkOwner_1 := h.Sum(nil)

	old2 := zg.Note{
		Value:   zg.NewGamma(10, 8),
		PkOwner: PkOwner_1,
		Rho:     big.NewInt(3333).Bytes(),
		Rand:    big.NewInt(4444).Bytes(),
	}
	old2.Cm = zg.Committment(old2.Value.Coins, old2.Value.Energy, big.NewInt(3333), big.NewInt(4444))

	skOld1 := sk_old_0_bytes[:] //[]byte("SK_OLD_1_XX_MIMC_ONLY")
	skOld2 := sk_old_1_bytes[:] //[]byte("SK_OLD_2_XX_MIMC_ONLY")

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

	tx_encapsulated := zn.TxEncapsulated{
		Kind:    0, //0 for default, 1 for one coin
		Payload: tx,
	}

	msg := zn.PackMessage("tx", tx_encapsulated)
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

func GenerateNote(Value zg.Gamma, PkOwner []byte, Rho []byte, Rand []byte) zg.Note {
	ret := zg.Note{
		Value:   Value,
		PkOwner: PkOwner,
		Rho:     Rho,
		Rand:    Rand,
	}
	ret.Cm = zg.Committment(Value.Coins, Value.Energy, new(big.Int).SetBytes(Rho), new(big.Int).SetBytes(Rand))
	return ret
}

func GenerateSk() []byte {
	sk, _ := zg.GenerateBls12377_frElement()
	var sk_bytes [32]byte = sk.Bytes()
	return sk_bytes[:]
}

func GeneratePk(sk []byte) []byte {
	h := mimcNative.NewMiMC()
	h.Write(sk)
	return h.Sum(nil)
}

// func (n *Node) SendTransactionRegister(validatorAddress string, targetAddress string, targetID int, globalCCS, globalCCSRegister constraint.ConstraintSystem, globalPK, globalPKRegister groth16.ProvingKey, globalVK, globalVKRegister groth16.VerifyingKey, kind bool) error {

// 	conn, err := net.Dial("tcp", validatorAddress)
// 	if err != nil {
// 		n.logger.Error().Err(err).Msgf("%s[Node %d] [Transaction] Error dialing %s\033[0m", getNodeColor(n.ID), n.ID, validatorAddress)
// 		return err
// 	}
// 	defer conn.Close()

// 	//compute PkBase
// 	sk_base, _ := zg.GenerateBls12377_frElement()
// 	sk_base_bytes := sk_base.Bytes()
// 	h := mimcNative.NewMiMC()
// 	h.Write(sk_base_bytes[:])
// 	pkBase := h.Sum(nil)
// 	skBase := sk_base_bytes[:]

// 	//compute PkIn
// 	sk_in, _ := zg.GenerateBls12377_frElement()
// 	sk_in_bytes := sk_in.Bytes()
// 	h = mimcNative.NewMiMC()
// 	h.Write(sk_in_bytes[:])
// 	pkIn := h.Sum(nil)
// 	skIn := sk_in_bytes[:]

// 	//compute PkOut
// 	sk_out, _ := zg.GenerateBls12377_frElement()
// 	sk_out_bytes := sk_out.Bytes()
// 	h = mimcNative.NewMiMC()
// 	h.Write(sk_out_bytes[:])
// 	pkOut := h.Sum(nil)
// 	skOut := sk_out_bytes[:]
// 	fmt.Println("skOut[0]: ", skOut[0])

// 	nBase := zg.Note{
// 		Value:   zg.NewGamma(12, 5),
// 		PkOwner: pkBase,
// 		Rho:     big.NewInt(1111).Bytes(),
// 		Rand:    big.NewInt(2222).Bytes(),
// 	}
// 	nBase.Cm = zg.Committment(nBase.Value.Coins, nBase.Value.Energy, big.NewInt(1111), big.NewInt(2222))

// 	//2 new notes
// 	new1 := zg.NewGamma(12, 5)

// 	// //Compute pkNew1
// 	// sk_new_1, _ := zg.GenerateBls12377_frElement()
// 	// sk_new_1_bytes := sk_new_1.Bytes()
// 	// h = mimcNative.NewMiMC()
// 	// h.Write(sk_new_1_bytes[:])
// 	// pkNew1 := h.Sum(nil)

// 	// 3) Build TxProverInputHighLevel
// 	inp := zg.TxProverInputHighLevelDefaultOneCoin{
// 		OldNote: nBase,
// 		OldSk:   skBase,
// 		NewVal:  new1,
// 		NewPk:   pkIn,
// 		EncKey:  n.DHExchanges[targetID].SharedSecret,
// 		R:       n.DHExchanges[targetID].Secret,
// 		//B:        b_bytes[:],
// 		G:   n.G,
// 		G_b: n.DHExchanges[targetID].PartnerPublic,
// 		G_r: n.DHExchanges[targetID].EphemeralPublic,
// 	}

// 	gammaIn := zg.NewGamma(12, 5)
// 	nIn := zg.Note{
// 		Value:   gammaIn,
// 		PkOwner: pkIn,
// 		Rho:     big.NewInt(1111).Bytes(),
// 		Rand:    big.NewInt(2222).Bytes(),
// 	}
// 	nIn.Cm = zg.Committment(nIn.Value.Coins, nIn.Value.Energy, big.NewInt(1111), big.NewInt(2222))

// 	//Encrypt [gammaIn, bid, skIn, pkOut]

// 	/*
// 		// Send "DH_G_r" containing A.
// 		dhPayload := zn.DHPayload{
// 			ID:      n.ID,
// 			SubType: "DH_G_r",
// 			Value:   A,
// 		}
// 		msg := zn.PackMessage("DiffieHellman", dhPayload)
// 		if err := zn.SendMessage(conn, msg); err != nil {
// 			n.logger.Error().Err(err).Msg("Erreur lors de l'envoi de DH_G_r")
// 			return err
// 		}
// 		n.logger.Info().Msg("DH_G_r envoyé avec succès.")
// 	*/

// 	//SEND TX

// 	////////////////////////

// 	// var rhoNew *big.Int
// 	// var randNew *big.Int

// 	// rhoNew = zg.RandBigInt()
// 	// randNew = zg.RandBigInt()
// 	bid := zg.RandBigInt()

// 	encVal := zg.BuildEncRegMimc(inp.EncKey, gammaIn, pkOut, skIn, bid)
// 	fmt.Println("Eh pourtant: ", encVal)

// 	///{*pk_enc, *skIn_enc, *bid_enc, *coins_enc, *energy_enc}

// 	// get pk_out_enc
// 	pk_enc := encVal[0].Bytes()
// 	pk_enc_bytes := make([]byte, len(pk_enc))
// 	copy(pk_enc_bytes, pk_enc[:])
// 	//cNew.PkOwner = pk_enc_bytes

// 	// get coins_enc
// 	coins_enc := encVal[3].Bytes()
// 	coins_enc_bytes := make([]byte, len(coins_enc))
// 	copy(coins_enc_bytes, coins_enc[:])
// 	//cNew.Value.Coins = new(big.Int).SetBytes(coins_enc_bytes)

// 	// get energy_enc
// 	energy_enc := encVal[4].Bytes()
// 	energy_enc_bytes := make([]byte, len(energy_enc))
// 	copy(energy_enc_bytes, energy_enc[:])
// 	//cNew.Value.Energy = new(big.Int).SetBytes(energy_enc_bytes)

// 	// get skIn_enc
// 	skIn_enc := encVal[1].Bytes()
// 	skIn_enc_bytes := make([]byte, len(skIn_enc))
// 	copy(skIn_enc_bytes, skIn_enc[:])
// 	//cNew.Rho = skIn_enc_bytes

// 	// get bid_enc
// 	bid_enc := encVal[2].Bytes()
// 	bid_enc_bytes := make([]byte, len(bid_enc))
// 	copy(bid_enc_bytes, bid_enc[:])
// 	//cNew.Rand = rand_enc_bytes

// 	inp_reg := zg.TxProverInputHighLevelRegister{
// 		InCoin:   big.NewInt(12).Bytes(),
// 		InEnergy: big.NewInt(5).Bytes(),
// 		CmIn:     nIn.Cm,
// 		CAux:     [5][]byte{pk_enc_bytes, skIn_enc_bytes, bid_enc_bytes, coins_enc_bytes, energy_enc_bytes},
// 		SkIn:     skIn,
// 		PkIn:     pkIn,
// 		PkOut:    pkOut,
// 		Bid:      bid.Bytes(),
// 		RhoIn:    big.NewInt(1111).Bytes(),
// 		RandIn:   big.NewInt(2222).Bytes(),
// 		InVal:    gammaIn,
// 		EncKey:   n.DHExchanges[targetID].SharedSecret,
// 		R:        n.DHExchanges[targetID].Secret,
// 		//B:        b_bytes[:],
// 		G:   n.G,
// 		G_b: n.DHExchanges[targetID].PartnerPublic,
// 		G_r: n.DHExchanges[targetID].EphemeralPublic,
// 	}

// 	//tx := TransactionOneCoin(inp, globalCCS, globalPK, conn, n.ID, targetAddress, targetID)
// 	fmt.Println("AVANT")
// 	//tx := TransactionOneCoin(inp, globalCCSOneCoin, globalPKOneCoin, conn, n.ID, targetAddress, targetID)
// 	fmt.Println("APRES")

// 	//fmt.Println("tx_encapsulated: ", tx_encapsulated)

// 	//PI_reg := ProofRegister(inp_reg, globalCCSRegister, globalPKRegister, conn, n.ID, targetAddress, targetID)
// 	///PI_reg := ProofRegister(inp_reg, globalCCSRegister, globalPKRegister, conn, n.ID, targetAddress, targetID)

// 	piReg, pubReg, Ip, err := ProofRegister(inp_reg, globalCCSRegister, globalPKRegister)
// 	if err != nil {
// 		fmt.Printf("Error generating register proof: %v\n", err)
// 		return err
// 	}

// 	tx_encapsulated := zn.TxEncapsulated{
// 		Kind:    1, //0 for default, 1 for one coin
// 		Payload: tx,
// 	}

// 	txReg := zn.TxRegister{
// 		TxIn:      tx_encapsulated,
// 		CmIn:      inp_reg.CmIn,
// 		PiReg:     piReg,
// 		PubW:      pubReg,
// 		Ip:        Ip,
// 		AuxCipher: [5][]byte{pk_enc_bytes, skIn_enc_bytes, bid_enc_bytes, coins_enc_bytes, energy_enc_bytes},
// 		EncVal:    encVal,
// 	}

// 	//send

// 	msg := zn.PackMessage("register", txReg)
// 	if err := zn.SendMessage(conn, msg); err != nil {
// 		fmt.Printf("%s[Node %d] [Transaction] Error sending transaction: %v\033[0m\n", getNodeColor(n.ID), n.ID, err)
// 		return nil
// 	} else {
// 		fmt.Printf("%s[Node %d] [Transaction] Transaction sent successfully for validation\033[0m\n", getNodeColor(n.ID), n.ID)
// 	}

// 	////////////////////////

// 	// msg := zn.PackMessage("tx", tx_encapsulated)
// 	// if err := zn.SendMessage(conn, msg); err != nil {
// 	// 	fmt.Printf("%s[Node %d] [Transaction] Error sending transaction: %v\033[0m\n", getNodeColor(n.ID), n.ID, err)
// 	// 	return nil
// 	// }

// 	// n.logger.Info().Msg(fmt.Sprintf("%s[Node %d] [Transaction] Transaction sent successfully for validation\033[0m", getNodeColor(n.ID), n.ID))

// 	// Send the transaction
// 	//msg := zn.PackMessage("tx", proof)

// 	/*
// 		// Send "DH_G_r" containing A.
// 		dhPayload := zn.DHPayload{
// 			ID:      n.ID,
// 			SubType: "DH_G_r",
// 			Value:   A,
// 		}
// 		msg := zn.PackMessage("DiffieHellman", dhPayload)
// 		if err := zn.SendMessage(conn, msg); err != nil {
// 			n.logger.Error().Err(err).Msg("Erreur lors de l'envoi de DH_G_r")
// 			return err
// 		}
// 		n.logger.Info().Msg("DH_G_r envoyé avec succès.")
// 	*/

// 	//
// 	return nil
// }

func (n *Node) SendTransactionRegisterN(
	validatorAddress string,
	targetAddress string,
	targetID int,
	// Paramètres existants pour les preuves et circuits
	globalCCSOneCoin constraint.ConstraintSystem,
	globalPKOneCoin groth16.ProvingKey,
	globalVKOneCoin groth16.VerifyingKey,
	globalCCSRegister constraint.ConstraintSystem,
	globalPKRegister groth16.ProvingKey,
	globalVKRegister groth16.VerifyingKey,
	// Paramètres supplémentaires nécessaires pour construire l'input de la transaction
	nBase zg.Note, // pour OldNote
	skBase []byte, // pour OldSk
	//new1 zg.Gamma, // pour NewVal
	pkIn []byte, // pour NewPk (et utilisé dans l'input de register)
	gammaIn zg.Gamma, // pour le paramètre gamma dans BuildEncRegMimc et InVal
	pkOut []byte, // pour le paramètre pkOut de BuildEncRegMimc et PkOut dans l'input de register
	skIn []byte, // pour skIn (dans BuildEncRegMimc et inp_reg)
	bid *big.Int, // pour bid (et son utilisation en bid.Bytes())
	nIn zg.Note, // pour accéder à nIn.Cm (votre type doit contenir le champ Cm)
	// Paramètres pour la transaction one coin

	// Autres paramètres
	kind bool,
) error {

	// Établir la connexion TCP
	conn, err := net.Dial("tcp", validatorAddress)
	if err != nil {
		n.logger.Error().Err(err).Msgf("%s[Node %d] [Transaction] Error dialing %s\033[0m", getNodeColor(n.ID), n.ID, validatorAddress)
		return err
	}
	defer conn.Close()

	//c.PkOut, c.SkIn, c.Bid, c.GammaInCoins, c.GammaInEnergy, c.EncKey)

	// Construction de l'input de la preuve pour une transaction one coin
	inp := zg.TxProverInputHighLevelDefaultOneCoin{
		OldNote: nBase,
		OldSk:   skBase,
		NewVal:  gammaIn,
		NewPk:   pkIn,
		EncKey:  n.DHExchanges[targetID].SharedSecret,
		R:       n.DHExchanges[targetID].Secret,
		// B:      b_bytes[:], // à décommenter et définir si nécessaire
		G:   n.G,
		G_b: n.DHExchanges[targetID].PartnerPublic,
		G_r: n.DHExchanges[targetID].EphemeralPublic,
	}

	// Appel de la fonction de chiffrement avec les paramètres requis
	encVal := zg.BuildEncRegMimc(inp.EncKey, gammaIn, pkOut, skIn, bid)

	//decVal, _ := zg.BuildDecRegMimc(inp.EncKey, encVal)

	// Extraction et copie des différents éléments chiffrés
	pk_enc := encVal[0].Bytes()
	pk_enc_bytes := make([]byte, len(pk_enc))
	copy(pk_enc_bytes, pk_enc[:])

	coins_enc := encVal[3].Bytes()
	coins_enc_bytes := make([]byte, len(coins_enc))
	copy(coins_enc_bytes, coins_enc[:])

	energy_enc := encVal[4].Bytes()
	energy_enc_bytes := make([]byte, len(energy_enc))
	copy(energy_enc_bytes, energy_enc[:])

	skIn_enc := encVal[1].Bytes()
	skIn_enc_bytes := make([]byte, len(skIn_enc))
	copy(skIn_enc_bytes, skIn_enc[:])

	bid_enc := encVal[2].Bytes()
	bid_enc_bytes := make([]byte, len(bid_enc))
	copy(bid_enc_bytes, bid_enc[:])

	// Construction de l'input pour la preuve d'enregistrement
	inp_reg := zg.TxProverInputHighLevelRegister{
		InCoin:   gammaIn.Coins.Bytes(),  //big.NewInt(12).Bytes(),
		InEnergy: gammaIn.Energy.Bytes(), //big.NewInt(5).Bytes(),
		CmIn:     nIn.Cm,
		CAux:     [5][]byte{pk_enc_bytes, skIn_enc_bytes, bid_enc_bytes, coins_enc_bytes, energy_enc_bytes},
		SkIn:     skIn,
		PkIn:     pkIn,
		PkOut:    pkOut,
		Bid:      bid.Bytes(),
		RhoIn:    big.NewInt(1111).Bytes(),
		RandIn:   big.NewInt(2222).Bytes(),
		InVal:    gammaIn,
		EncKey:   n.DHExchanges[targetID].SharedSecret,
		R:        n.DHExchanges[targetID].Secret,
		// B:      b_bytes[:], // à décommenter et définir si nécessaire
		G:   n.G,
		G_b: n.DHExchanges[targetID].PartnerPublic,
		G_r: n.DHExchanges[targetID].EphemeralPublic,
	}

	/*
		cm := zg.Committment(inp.NewVal.Coins, inp.NewVal.Energy,
			rhoNew, randNew)
	*/

	rhoNew := zg.RandBigInt()
	randNew := zg.RandBigInt()

	// Construction de la transaction one coin
	tx := TransactionOneCoin(inp, globalCCSOneCoin, globalPKOneCoin, conn, n.ID, targetAddress, targetID, rhoNew, randNew)

	// Génération de la preuve d'enregistrement
	piReg, pubReg, Ip, err := ProofRegister(inp_reg, globalCCSRegister, globalPKRegister)
	if err != nil {
		fmt.Printf("Error generating register proof: %v\n", err)
		return err
	}

	// Encapsulation de la transaction
	tx_encapsulated := zn.TxEncapsulated{
		Kind:    1, // 0 pour default, 1 pour one coin
		Payload: tx,
	}

	txReg := zn.TxRegister{
		TxIn:      tx_encapsulated,
		CmIn:      inp_reg.CmIn,
		PiReg:     piReg,
		PubW:      pubReg,
		Ip:        Ip,
		AuxCipher: [5][]byte{pk_enc_bytes, skIn_enc_bytes, bid_enc_bytes, coins_enc_bytes, energy_enc_bytes},
		EncVal:    encVal, //FALSE, TO REMOVE
		Kind:      kind,
	}

	// Packager et envoyer le message
	msg := zn.PackMessage("register", txReg)
	if err := zn.SendMessage(conn, msg); err != nil {
		fmt.Printf("%s[Node %d] [Transaction] Error sending transaction: %v\033[0m\n", getNodeColor(n.ID), n.ID, err)
		return nil
	} else {
		fmt.Printf("%s[Node %d] [Transaction] Transaction sent successfully for validation\033[0m\n", getNodeColor(n.ID), n.ID)
	}

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
		ip.PkOld[i] = inp.OldNotes[i].PkOwner

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

func TransactionOneCoin(inp zg.TxProverInputHighLevelDefaultOneCoin, globalCCSOneCoin constraint.ConstraintSystem, globalPKOneCoin groth16.ProvingKey, conn net.Conn, ID int, targetAddress string, targetID int, rhoNew *big.Int, randNew *big.Int) zn.TxDefaultOneCoinPayload {
	// 1) snOld[i] = MiMC(skOld[i], RhoOld[i]) off-circuit
	var snOld []byte
	sn := zg.CalcSerialMimc(inp.OldSk, inp.OldNote.Rho)
	snOld = sn
	// 2) Generate (rhoNew, randNew), cmNew, cNew
	//var rhoNew *big.Int
	//var randNew *big.Int
	var cmNew []byte
	//var cNew [2][][]byte
	var cNew zg.Note

	//rhoNew = zg.RandBigInt()
	//randNew = zg.RandBigInt()
	cm := zg.Committment(inp.NewVal.Coins, inp.NewVal.Energy,
		rhoNew, randNew)
	cmNew = cm
	encVal := zg.BuildEncMimc(inp.EncKey, inp.NewPk,
		inp.NewVal.Coins, inp.NewVal.Energy,
		rhoNew, randNew, cm)

	//ICI

	// get pk_enc
	pk_enc := encVal[0].Bytes()
	pk_enc_bytes := make([]byte, len(pk_enc))
	copy(pk_enc_bytes, pk_enc[:])
	cNew.PkOwner = pk_enc_bytes

	// get coins_enc
	coins_enc := encVal[1].Bytes()
	coins_enc_bytes := make([]byte, len(coins_enc))
	copy(coins_enc_bytes, coins_enc[:])
	cNew.Value.Coins = new(big.Int).SetBytes(coins_enc_bytes)

	// get energy_enc
	energy_enc := encVal[2].Bytes()
	energy_enc_bytes := make([]byte, len(energy_enc))
	copy(energy_enc_bytes, energy_enc[:])
	cNew.Value.Energy = new(big.Int).SetBytes(energy_enc_bytes)

	// get rho_enc
	rho_enc := encVal[3].Bytes()
	rho_enc_bytes := make([]byte, len(rho_enc))
	copy(rho_enc_bytes, rho_enc[:])
	cNew.Rho = rho_enc_bytes

	// get rand_enc
	rand_enc := encVal[4].Bytes()
	rand_enc_bytes := make([]byte, len(rand_enc))
	copy(rand_enc_bytes, rand_enc[:])
	cNew.Rand = rand_enc_bytes

	// get cm_enc
	cm_enc := encVal[5].Bytes()
	cm_enc_bytes := make([]byte, len(cm_enc))
	copy(cm_enc_bytes, cm_enc[:])
	cNew.Cm = cm_enc_bytes

	// 3) Build InputProver
	var ip zg.InputProverDefaultOneCoin
	// old
	ip.OldCoin = inp.OldNote.Value.Coins
	ip.OldEnergy = inp.OldNote.Value.Energy
	ip.CmOld = inp.OldNote.Cm
	ip.SnOld = snOld
	ip.PkOld = inp.OldNote.PkOwner

	ip.SkOld = new(big.Int).SetBytes(inp.OldSk)
	ip.RhoOld = new(big.Int).SetBytes(inp.OldNote.Rho)
	ip.RandOld = new(big.Int).SetBytes(inp.OldNote.Rand)
	// new
	ip.NewCoin = inp.NewVal.Coins
	ip.NewEnergy = inp.NewVal.Energy
	ip.CmNew = cmNew

	// pk

	// allocate with make
	ip.CNew = make([][]byte, 6)
	ip.CNew[0] = cNew.PkOwner

	// coins
	ip.CNew[1] = cNew.Value.Coins.Bytes()

	// energy
	ip.CNew[2] = cNew.Value.Energy.Bytes()

	// rho
	ip.CNew[3] = cNew.Rho

	// rand
	ip.CNew[4] = cNew.Rand

	// cm
	ip.CNew[5] = cNew.Cm

	ip.PkNew = new(big.Int).SetBytes(inp.NewPk)
	ip.RhoNew = rhoNew
	ip.RandNew = randNew

	ip.R = inp.R
	//ip.B = inp.B
	ip.G = inp.G
	ip.G_b = inp.G_b
	ip.G_r = inp.G_r
	ip.EncKey = inp.EncKey

	wc, _ := ip.BuildWitness()
	w, _ := frontend.NewWitness(wc, ecc.BW6_761.ScalarField())

	wPub, _ := w.Public()
	var pubBuf bytes.Buffer
	if _, err := wPub.WriteTo(&pubBuf); err != nil {
		panic(err)
	}

	// 4) Generate proof
	_ = time.Now()
	proof, err := groth16.Prove(globalCCSOneCoin, globalPKOneCoin, w)
	if err != nil {
		panic(err)
	}

	var buf bytes.Buffer
	proof.WriteTo(&buf)

	txResult := zg.TxResultDefaultOneCoin{
		SnOld: snOld,
		CmNew: cmNew,
		CNew:  cNew, //[2]zg.Note{[0], cNew[1]},
		Proof: buf.Bytes(),

		RhoNew:  rhoNew,
		RandNew: randNew,
		SkOld:   inp.OldSk,
		RhoOld:  new(big.Int).SetBytes(inp.OldNote.Rho),
		RandOld: new(big.Int).SetBytes(inp.OldNote.Rand),
		PkNew:   new(big.Int).SetBytes(inp.NewPk),
	}

	return zn.TxDefaultOneCoinPayload{
		TxResult:      txResult,
		Old:           inp.OldNote,
		NewVal:        inp.NewVal,
		ID:            ID,
		TargetAddress: targetAddress,
		TargetID:      targetID,
		PublicWitness: pubBuf.Bytes(),
		EncVal:        encVal,
	}
}

func TransactionNCoin(
	//N int,
	inp zg.TxProverInputHighLevelDefaultNCoin, // type adapté pour N coins
	globalCCSN []constraint.ConstraintSystem,
	globalPKN []groth16.ProvingKey,
	conn net.Conn,
	ID int,
	targetAddress string,
	targetID int,
	rhoNewList []*big.Int,
	randNewList []*big.Int,
) zn.TxDefaultNCoinPayload {
	coinCount := len(inp.OldNote)

	// 1) Calculer snOld pour chaque coin
	var snOldList [][]byte
	for i := 0; i < coinCount; i++ {
		sn := zg.CalcSerialMimc(inp.OldSk[i], inp.OldNote[i].Rho)
		snOldList = append(snOldList, sn)
	}

	// 2) Pour chaque coin, générer (rhoNew, randNew), cmNew et cNew
	var cmNewList [][]byte
	var cNewList []zg.Note
	// Chaque élément de encValList est un tableau de 6 éléments (valeurs encryptées)
	var encValList [][6]bls12377_fp.Element

	for i := 0; i < coinCount; i++ {
		// Calcul du commitment pour le nouveau coin
		cm := zg.Committment(inp.NewVal[i].Coins, inp.NewVal[i].Energy,
			rhoNewList[i], randNewList[i])
		cmNewList = append(cmNewList, cm)

		// Calcul des valeurs encryptées
		encVal := zg.BuildEncMimc(inp.EncKey[i], inp.NewPk[i],
			inp.NewVal[i].Coins, inp.NewVal[i].Energy,
			rhoNewList[i], randNewList[i], cm)
		encValList = append(encValList, encVal)

		// Construction de la nouvelle note (cNew)
		var note zg.Note

		// Extraction de pk_enc
		pk_enc := encVal[0].Bytes()
		pk_enc_bytes := make([]byte, len(pk_enc))
		copy(pk_enc_bytes, pk_enc[:])
		note.PkOwner = pk_enc_bytes

		// Extraction de coins_enc
		coins_enc := encVal[1].Bytes()
		coins_enc_bytes := make([]byte, len(coins_enc))
		copy(coins_enc_bytes, coins_enc[:])
		note.Value.Coins = new(big.Int).SetBytes(coins_enc_bytes)

		// Extraction de energy_enc
		energy_enc := encVal[2].Bytes()
		energy_enc_bytes := make([]byte, len(energy_enc))
		copy(energy_enc_bytes, energy_enc[:])
		note.Value.Energy = new(big.Int).SetBytes(energy_enc_bytes)

		// Extraction de rho_enc
		rho_enc := encVal[3].Bytes()
		rho_enc_bytes := make([]byte, len(rho_enc))
		copy(rho_enc_bytes, rho_enc[:])
		note.Rho = rho_enc_bytes

		// Extraction de rand_enc
		rand_enc := encVal[4].Bytes()
		rand_enc_bytes := make([]byte, len(rand_enc))
		copy(rand_enc_bytes, rand_enc[:])
		note.Rand = rand_enc_bytes

		// Extraction de cm_enc
		cm_enc := encVal[5].Bytes()
		cm_enc_bytes := make([]byte, len(cm_enc))
		copy(cm_enc_bytes, cm_enc[:])
		note.Cm = cm_enc_bytes

		cNewList = append(cNewList, note)
	}

	// 3) Construire l'InputProver pour N coins
	var ip zg.InputProverDefaultNCoin

	// Partie "old" (chaque champ est une slice)
	ip.OldCoin = make([]*big.Int, coinCount)
	ip.OldEnergy = make([]*big.Int, coinCount)
	ip.CmOld = make([][]byte, coinCount)
	ip.SnOld = make([][]byte, coinCount)
	ip.PkOld = make([][]byte, coinCount)
	ip.SkOld = make([]*big.Int, coinCount)
	ip.RhoOld = make([]*big.Int, coinCount)
	ip.RandOld = make([]*big.Int, coinCount)

	for i := 0; i < coinCount; i++ {
		ip.OldCoin[i] = inp.OldNote[i].Value.Coins
		ip.OldEnergy[i] = inp.OldNote[i].Value.Energy
		ip.CmOld[i] = inp.OldNote[i].Cm
		ip.SnOld[i] = snOldList[i]
		ip.PkOld[i] = inp.OldNote[i].PkOwner
		ip.SkOld[i] = new(big.Int).SetBytes(inp.OldSk[i])
		ip.RhoOld[i] = new(big.Int).SetBytes(inp.OldNote[i].Rho)
		ip.RandOld[i] = new(big.Int).SetBytes(inp.OldNote[i].Rand)
	}

	// Partie "new" (chaque champ est une slice)
	ip.NewCoin = make([]*big.Int, coinCount)
	ip.NewEnergy = make([]*big.Int, coinCount)
	ip.CmNew = make([][]byte, coinCount)
	// CNew est une slice de slices : pour chaque coin, 6 éléments comme dans TransactionOneCoin
	ip.CNew = make([][][]byte, coinCount)
	ip.R = make([][]byte, coinCount)
	ip.G = make([]bls12377.G1Affine, coinCount)
	ip.G_b = make([]bls12377.G1Affine, coinCount)
	ip.G_r = make([]bls12377.G1Affine, coinCount)
	ip.EncKey = make([]bls12377.G1Affine, coinCount)

	for i := 0; i < coinCount; i++ {
		ip.NewCoin[i] = inp.NewVal[i].Coins
		ip.NewEnergy[i] = inp.NewVal[i].Energy
		ip.CmNew[i] = cmNewList[i]

		coinCNew := make([][]byte, 6)
		coinCNew[0] = cNewList[i].PkOwner
		coinCNew[1] = cNewList[i].Value.Coins.Bytes()
		coinCNew[2] = cNewList[i].Value.Energy.Bytes()
		coinCNew[3] = cNewList[i].Rho
		coinCNew[4] = cNewList[i].Rand
		coinCNew[5] = cNewList[i].Cm
		ip.CNew[i] = coinCNew

		// Les autres paramètres globaux restent inchangés
		ip.R[i] = inp.R[i]
		ip.G[i] = inp.G[i]
		ip.G_b[i] = inp.G_b[i]
		ip.G_r[i] = inp.G_r[i]
		ip.EncKey[i] = inp.EncKey[i]
	}

	// Pour les clés publiques new (une par coin)
	ip.PkNew = make([]*big.Int, coinCount)
	for i := 0; i < coinCount; i++ {
		ip.PkNew[i] = new(big.Int).SetBytes(inp.NewPk[i])
	}
	ip.RhoNew = rhoNewList
	ip.RandNew = randNewList

	// //error if N!=2
	// if N != 2 {
	// 	panic("N must be 2")
	// }

	// Construction du witness
	var wc frontend.Circuit
	switch coinCount {
	case 2:
		wc, _ = ip.BuildWitness2()
	case 3:
		wc, _ = ip.BuildWitness3()
	default:
		wc, _ = ip.BuildWitness2()
	}
	w, _ := frontend.NewWitness(wc, ecc.BW6_761.ScalarField())

	wPub, _ := w.Public()
	var pubBuf bytes.Buffer
	if _, err := wPub.WriteTo(&pubBuf); err != nil {
		panic(err)
	}

	// 4) Générer la preuve
	proof, err := groth16.Prove(globalCCSN[coinCount], globalPKN[coinCount], w)
	if err != nil {
		panic(err)
	}
	var buf bytes.Buffer
	proof.WriteTo(&buf)

	// 5) Construire le résultat de la transaction
	var oldRhoList []*big.Int
	var oldRandList []*big.Int
	var newPkList []*big.Int
	for i := 0; i < coinCount; i++ {
		oldRhoList = append(oldRhoList, new(big.Int).SetBytes(inp.OldNote[i].Rho))
		oldRandList = append(oldRandList, new(big.Int).SetBytes(inp.OldNote[i].Rand))
		newPkList = append(newPkList, new(big.Int).SetBytes(inp.NewPk[i]))
	}

	txResult := zg.TxResultDefaultNCoin{
		SnOld:   snOldList,
		CmNew:   cmNewList,
		CNew:    cNewList,
		Proof:   buf.Bytes(),
		RhoNew:  rhoNewList,
		RandNew: randNewList,
		SkOld:   inp.OldSk, // supposé être déjà une slice
		RhoOld:  oldRhoList,
		RandOld: oldRandList,
		PkNew:   newPkList,
	}

	return zn.TxDefaultNCoinPayload{
		TxResult:      txResult,
		Old:           inp.OldNote,
		NewVal:        inp.NewVal,
		ID:            ID,
		TargetAddress: targetAddress,
		TargetID:      targetID,
		PublicWitness: pubBuf.Bytes(),
		EncVal:        encValList,
	}
}

func TransactionF1(inp zg.TxProverInputHighLevelF1, globalCCSF1 constraint.ConstraintSystem, globalPKF1 groth16.ProvingKey, conn net.Conn, ID int, targetAddress string, targetID int) zn.TxF1Payload {

	// inp_c_0 := inp.C[0].Bytes()
	// inp_c_1 := inp.C[1].Bytes()
	// inp_c_2 := inp.C[2].Bytes()
	// inp_c_3 := inp.C[3].Bytes()
	// inp_c_4 := inp.C[4].Bytes()

	// Extraction et copie des différents éléments chiffrés
	pk_enc := inp.C[0].Bytes()
	pk_enc_bytes := make([]byte, len(pk_enc))
	copy(pk_enc_bytes, pk_enc[:])

	coins_enc := inp.C[3].Bytes()
	coins_enc_bytes := make([]byte, len(coins_enc))
	copy(coins_enc_bytes, coins_enc[:])

	energy_enc := inp.C[4].Bytes()
	energy_enc_bytes := make([]byte, len(energy_enc))
	copy(energy_enc_bytes, energy_enc[:])

	skIn_enc := inp.C[1].Bytes()
	skIn_enc_bytes := make([]byte, len(skIn_enc))
	copy(skIn_enc_bytes, skIn_enc[:])

	bid_enc := inp.C[2].Bytes()
	bid_enc_bytes := make([]byte, len(bid_enc))
	copy(bid_enc_bytes, bid_enc[:])

	ip_ := zg.InputTxF1{
		InCoin:   new(big.Int).SetBytes(inp.InCoin),
		InEnergy: new(big.Int).SetBytes(inp.InEnergy),
		InCm:     new(big.Int).SetBytes(inp.InCm),
		InSn:     new(big.Int).SetBytes(inp.InSn),
		InPk:     new(big.Int).SetBytes(inp.InPk),
		InSk:     new(big.Int).SetBytes(inp.InSk),
		InRho:    new(big.Int).SetBytes(inp.InRho),
		InRand:   new(big.Int).SetBytes(inp.InRand),

		OutCoin:   new(big.Int).SetBytes(inp.OutCoin),
		OutEnergy: new(big.Int).SetBytes(inp.OutEnergy),
		OutCm:     new(big.Int).SetBytes(inp.OutCm),
		OutSn:     new(big.Int).SetBytes(inp.OutSn),
		OutPk:     new(big.Int).SetBytes(inp.OutPk),
		OutRho:    new(big.Int).SetBytes(inp.OutRho),
		OutRand:   new(big.Int).SetBytes(inp.OutRand),

		SkT: inp.SkT,
		//SnIn:  new(big.Int).SetBytes(inp.SnIn),
		//CmOut: new(big.Int).SetBytes(inp.CmOut),
		//pk_enc_bytes, skIn_enc_bytes, bid_enc_bytes, coins_enc_bytes, energy_enc_bytes},
		C: [5][]byte{
			pk_enc_bytes,
			skIn_enc_bytes,
			bid_enc_bytes,
			coins_enc_bytes,
			energy_enc_bytes,
			// new(big.Int).SetBytes(pk_enc_bytes),
			// new(big.Int).SetBytes(coins_enc_bytes),
			// new(big.Int).SetBytes(energy_enc_bytes),
			// new(big.Int).SetBytes(skIn_enc_bytes),
			// new(big.Int).SetBytes(bid_enc_bytes),
		},
		DecVal: inp.DecVal,
		EncKey: inp.EncKey,

		R:   new(big.Int).SetBytes(inp.R),
		G:   inp.G,
		G_b: inp.G_b,
		G_r: inp.G_r,
	}

	c, err := ip_.BuildWitness()
	if err != nil {
		panic(err)
	}

	fmt.Println("CIRCUIT F1")

	// fmt.Println("=ip_", ip_)

	w, _ := frontend.NewWitness(c, ecc.BW6_761.ScalarField())

	fmt.Println("GENERONS CETTE PREUVE")
	// 4) Generate proof
	_ = time.Now()
	proof, err := groth16.Prove(globalCCSF1, globalPKF1, w)
	if err != nil {
		panic(err)
	}
	fmt.Println("PREUVE GENEREE")

	var buf bytes.Buffer
	proof.WriteTo(&buf)

	// // 1) snOld[i] = MiMC(skOld[i], RhoOld[i]) off-circuit
	// var snOld []byte
	// sn := zg.CalcSerialMimc(inp.OldSk, inp.OldNote.Rho)
	// snOld = sn
	// // 2) Generate (rhoNew, randNew), cmNew, cNew
	// var rhoNew *big.Int
	// var randNew *big.Int
	// var cmNew []byte
	// //var cNew [2][][]byte
	// var cNew zg.Note

	// rhoNew = zg.RandBigInt()
	// randNew = zg.RandBigInt()
	// cm := zg.Committment(inp.NewVal.Coins, inp.NewVal.Energy,
	// 	rhoNew, randNew)
	// cmNew = cm
	// encVal := zg.BuildEncMimc(inp.EncKey, inp.NewPk,
	// 	inp.NewVal.Coins, inp.NewVal.Energy,
	// 	rhoNew, randNew, cm)

	// //ICI

	// // get pk_enc
	// pk_enc := encVal[0].Bytes()
	// pk_enc_bytes := make([]byte, len(pk_enc))
	// copy(pk_enc_bytes, pk_enc[:])
	// cNew.PkOwner = pk_enc_bytes

	// // get coins_enc
	// coins_enc := encVal[1].Bytes()
	// coins_enc_bytes := make([]byte, len(coins_enc))
	// copy(coins_enc_bytes, coins_enc[:])
	// cNew.Value.Coins = new(big.Int).SetBytes(coins_enc_bytes)

	// // get energy_enc
	// energy_enc := encVal[2].Bytes()
	// energy_enc_bytes := make([]byte, len(energy_enc))
	// copy(energy_enc_bytes, energy_enc[:])
	// cNew.Value.Energy = new(big.Int).SetBytes(energy_enc_bytes)

	// // get rho_enc
	// rho_enc := encVal[3].Bytes()
	// rho_enc_bytes := make([]byte, len(rho_enc))
	// copy(rho_enc_bytes, rho_enc[:])
	// cNew.Rho = rho_enc_bytes

	// // get rand_enc
	// rand_enc := encVal[4].Bytes()
	// rand_enc_bytes := make([]byte, len(rand_enc))
	// copy(rand_enc_bytes, rand_enc[:])
	// cNew.Rand = rand_enc_bytes

	// // get cm_enc
	// cm_enc := encVal[5].Bytes()
	// cm_enc_bytes := make([]byte, len(cm_enc))
	// copy(cm_enc_bytes, cm_enc[:])
	// cNew.Cm = cm_enc_bytes

	// // 3) Build InputProver
	// var ip zg.InputProverDefaultOneCoin
	// // old
	// ip.OldCoin = inp.OldNote.Value.Coins
	// ip.OldEnergy = inp.OldNote.Value.Energy
	// ip.CmOld = inp.OldNote.Cm
	// ip.SnOld = snOld
	// ip.PkOld = inp.OldNote.PkOwner

	// ip.SkOld = new(big.Int).SetBytes(inp.OldSk)
	// ip.RhoOld = new(big.Int).SetBytes(inp.OldNote.Rho)
	// ip.RandOld = new(big.Int).SetBytes(inp.OldNote.Rand)
	// // new
	// ip.NewCoin = inp.NewVal.Coins
	// ip.NewEnergy = inp.NewVal.Energy
	// ip.CmNew = cmNew

	// // pk

	// // allocate with make
	// ip.CNew = make([][]byte, 6)
	// ip.CNew[0] = cNew.PkOwner

	// // coins
	// ip.CNew[1] = cNew.Value.Coins.Bytes()

	// // energy
	// ip.CNew[2] = cNew.Value.Energy.Bytes()

	// // rho
	// ip.CNew[3] = cNew.Rho

	// // rand
	// ip.CNew[4] = cNew.Rand

	// // cm
	// ip.CNew[5] = cNew.Cm

	// ip.PkNew = new(big.Int).SetBytes(inp.NewPk)
	// ip.RhoNew = rhoNew
	// ip.RandNew = randNew

	// ip.R = inp.R
	// //ip.B = inp.B
	// ip.G = inp.G
	// ip.G_b = inp.G_b
	// ip.G_r = inp.G_r
	// ip.EncKey = inp.EncKey

	// wc, _ := ip.BuildWitness()
	// w, _ := frontend.NewWitness(wc, ecc.BW6_761.ScalarField())

	// wPub, _ := w.Public()
	// var pubBuf bytes.Buffer
	// if _, err := wPub.WriteTo(&pubBuf); err != nil {
	// 	panic(err)
	// }

	// // 4) Generate proof
	// _ = time.Now()
	// proof, err := groth16.Prove(globalCCSOneCoin, globalPKOneCoin, w)
	// if err != nil {
	// 	panic(err)
	// }

	// var buf bytes.Buffer
	// proof.WriteTo(&buf)

	// txResult := zg.TxResultDefaultOneCoin{
	// 	SnOld: snOld,
	// 	CmNew: cmNew,
	// 	CNew:  cNew, //[2]zg.Note{[0], cNew[1]},
	// 	Proof: buf.Bytes(),

	// 	RhoNew:  rhoNew,
	// 	RandNew: randNew,
	// 	SkOld:   inp.OldSk,
	// 	RhoOld:  new(big.Int).SetBytes(inp.OldNote.Rho),
	// 	RandOld: new(big.Int).SetBytes(inp.OldNote.Rand),
	// 	PkNew:   new(big.Int).SetBytes(inp.NewPk),
	// }

	// return zn.TxDefaultOneCoinPayload{
	// 	TxResult:      txResult,
	// 	Old:           inp.OldNote,
	// 	NewVal:        inp.NewVal,
	// 	ID:            ID,
	// 	TargetAddress: targetAddress,
	// 	TargetID:      targetID,
	// 	PublicWitness: pubBuf.Bytes(),
	// 	EncVal:        encVal,
	// }

	return zn.TxF1Payload{
		Proof: buf.Bytes(),
	}
}

func TransactionFN(inp zg.TxProverInputHighLevelFN, globalCCSFN []constraint.ConstraintSystem, globalPKFN []groth16.ProvingKey, conn net.Conn, ID int, targetAddress string, targetID int) zn.TxFNPayload {

	// Conversion des champs coin‑spécifiques de [][]byte en []frontend.Variable pour chaque coin.
	coinCount := len(inp.InCoin)
	var inCoinConv, inEnergyConv, inCmConv, inSnConv, inPkConv, inSkConv, inRhoConv, inRandConv []frontend.Variable
	var outCoinConv, outEnergyConv, outCmConv, outSnConv, outPkConv, outRhoConv, outRandConv []frontend.Variable
	var RConv []frontend.Variable

	for i := 0; i < coinCount; i++ {
		inCoinConv = append(inCoinConv, new(big.Int).SetBytes(inp.InCoin[i]))
		inEnergyConv = append(inEnergyConv, new(big.Int).SetBytes(inp.InEnergy[i]))
		inCmConv = append(inCmConv, new(big.Int).SetBytes(inp.InCm[i]))
		inSnConv = append(inSnConv, new(big.Int).SetBytes(inp.InSn[i]))
		inPkConv = append(inPkConv, new(big.Int).SetBytes(inp.InPk[i]))
		inSkConv = append(inSkConv, new(big.Int).SetBytes(inp.InSk[i]))
		inRhoConv = append(inRhoConv, new(big.Int).SetBytes(inp.InRho[i]))
		inRandConv = append(inRandConv, new(big.Int).SetBytes(inp.InRand[i]))

		outCoinConv = append(outCoinConv, new(big.Int).SetBytes(inp.OutCoin[i]))
		outEnergyConv = append(outEnergyConv, new(big.Int).SetBytes(inp.OutEnergy[i]))
		outCmConv = append(outCmConv, new(big.Int).SetBytes(inp.OutCm[i]))
		outSnConv = append(outSnConv, new(big.Int).SetBytes(inp.OutSn[i]))
		outPkConv = append(outPkConv, new(big.Int).SetBytes(inp.OutPk[i]))
		outRhoConv = append(outRhoConv, new(big.Int).SetBytes(inp.OutRho[i]))
		outRandConv = append(outRandConv, new(big.Int).SetBytes(inp.OutRand[i]))

		RConv = append(RConv, new(big.Int).SetBytes(inp.R[i])) //NOT GOOD
	}

	var ip_ zg.InputTxFN
	//var c frontend.Circuit
	var buf bytes.Buffer

	// // --- Extraction des éléments chiffrés pour le coin 0 ---
	// pk_enc0 := inp.C[0][0].Bytes()
	// pk_enc0_bytes := make([]byte, len(pk_enc0))
	// copy(pk_enc0_bytes, pk_enc0[:])

	// coins_enc0 := inp.C[0][3].Bytes()
	// coins_enc0_bytes := make([]byte, len(coins_enc0))
	// copy(coins_enc0_bytes, coins_enc0[:])

	// energy_enc0 := inp.C[0][4].Bytes()
	// energy_enc0_bytes := make([]byte, len(energy_enc0))
	// copy(energy_enc0_bytes, energy_enc0[:])

	// skIn_enc0 := inp.C[0][1].Bytes()
	// skIn_enc0_bytes := make([]byte, len(skIn_enc0))
	// copy(skIn_enc0_bytes, skIn_enc0[:])

	// bid_enc0 := inp.C[0][2].Bytes()
	// bid_enc0_bytes := make([]byte, len(bid_enc0))
	// copy(bid_enc0_bytes, bid_enc0[:])

	// // --- Extraction des éléments chiffrés pour le coin 1 ---
	// pk_enc1 := inp.C[1][0].Bytes()
	// pk_enc1_bytes := make([]byte, len(pk_enc1))
	// copy(pk_enc1_bytes, pk_enc1[:])

	// coins_enc1 := inp.C[1][3].Bytes()
	// coins_enc1_bytes := make([]byte, len(coins_enc1))
	// copy(coins_enc1_bytes, coins_enc1[:])

	// energy_enc1 := inp.C[1][4].Bytes()
	// energy_enc1_bytes := make([]byte, len(energy_enc1))
	// copy(energy_enc1_bytes, energy_enc1[:])

	// skIn_enc1 := inp.C[1][1].Bytes()
	// skIn_enc1_bytes := make([]byte, len(skIn_enc1))
	// copy(skIn_enc1_bytes, skIn_enc1[:])

	// bid_enc1 := inp.C[1][2].Bytes()
	// bid_enc1_bytes := make([]byte, len(bid_enc1))
	// copy(bid_enc1_bytes, bid_enc1[:])

	// // Constitution des tableaux d'encryption pour chaque coin.
	// var C0 [5][]byte = [5][]byte{
	// 	pk_enc0_bytes,
	// 	skIn_enc0_bytes,
	// 	bid_enc0_bytes,
	// 	coins_enc0_bytes,
	// 	energy_enc0_bytes,
	// }
	// var C1 [5][]byte = [5][]byte{
	// 	pk_enc1_bytes,
	// 	skIn_enc1_bytes,
	// 	bid_enc1_bytes,
	// 	coins_enc1_bytes,
	// 	energy_enc1_bytes,
	// }

	res := ExtractEncryptedCoins(&inp, coinCount)

	// Construction de l'input pour le circuit multi‑coin (N=2)
	ip_ = zg.InputTxFN{
		InCoin:    inCoinConv,
		InEnergy:  inEnergyConv,
		InCm:      inCmConv,
		InSn:      inSnConv,
		InPk:      inPkConv,
		InSk:      inSkConv,
		InRho:     inRhoConv,
		InRand:    inRandConv,
		OutCoin:   outCoinConv,
		OutEnergy: outEnergyConv,
		OutCm:     outCmConv,
		OutSn:     outSnConv,
		OutPk:     outPkConv,
		OutRho:    outRhoConv,
		OutRand:   outRandConv,
		// Pour le champ C, on construit un slice contenant les tableaux pour chaque coin.
		C:      res,        //[][5][]byte{C0, C1},
		DecVal: inp.DecVal, // On suppose que inp.DecVal est déjà un slice avec 2 éléments.
		// Paramètres globaux
		SkT:    inp.SkT,
		EncKey: inp.EncKey,
		R:      RConv, //new(big.Int).SetBytes(inp.R), // On suppose que inp.R est un slice (ex. avec la valeur globale en première position).
		G:      inp.G,
		G_b:    inp.G_b,
		G_r:    inp.G_r,
	}

	var err error
	var cc frontend.Circuit
	// Construction du witness via la méthode BuildWitness de InputTxFN.

	switch coinCount {
	case 2:
		cc, err = ip_.BuildWitness2()
		if err != nil {
			panic(err)
		}
	case 3:
		cc, err = ip_.BuildWitness3()
		if err != nil {
			panic(err)
		}
	default:
		cc, err = ip_.BuildWitness2()
		if err != nil {
			panic(err)
		}
	}

	//fmt.Println("CIRCUIT F2 (N=2)")
	w, _ := frontend.NewWitness(cc, ecc.BW6_761.ScalarField())

	fmt.Println("GÉNÉRATION DE LA PREUVE...")
	proof, err := groth16.Prove(globalCCSFN[coinCount], globalPKFN[coinCount], w)
	if err != nil {
		panic(err)
	}
	fmt.Println("PREUVE GÉNÉRÉE")

	proof.WriteTo(&buf)

	return zn.TxFNPayload{
		Proof: buf.Bytes(),
	}
}

func ProofRegister(
	inp zg.TxProverInputHighLevelRegister,
	ccsRegister constraint.ConstraintSystem,
	pkRegister groth16.ProvingKey,
) (proofBytes []byte, publicWitnessBytes []byte, ipr zg.InputProverRegister, err error) {

	// ========== 1) Construire InputProverRegister ==========
	//    (cette struct aura les champs en big.Int, bytes, etc.)
	var ip zg.InputProverRegister

	// Remplir ip à partir de inp
	//   - public: ip.CmIn, ip.CAux, ip.GammaInCoins, ...
	//   - privé:  ip.InCoin, ip.RhoIn, ...
	//   - G, G_b, ...
	//   - etc.
	// Exemple:
	ip.CmIn = inp.CmIn
	ip.CAux = inp.CAux
	ip.GammaInCoins = new(big.Int).SetBytes(inp.InVal.Coins.Bytes())
	ip.GammaInEnergy = new(big.Int).SetBytes(inp.InVal.Energy.Bytes())
	ip.Bid = new(big.Int).SetBytes(inp.Bid)

	ip.InCoin = new(big.Int).SetBytes(inp.InCoin)
	ip.InEnergy = new(big.Int).SetBytes(inp.InEnergy)
	ip.RhoIn = new(big.Int).SetBytes(inp.RhoIn)
	ip.RandIn = new(big.Int).SetBytes(inp.RandIn)
	ip.SkIn = new(big.Int).SetBytes(inp.SkIn)
	ip.PkIn = new(big.Int).SetBytes(inp.PkIn)
	ip.PkOut = new(big.Int).SetBytes(inp.PkOut)
	ip.R = new(big.Int).SetBytes(inp.R)

	// Paramètres G, G_b, G_r, EncKey
	ip.G = inp.G
	ip.G_b = inp.G_b
	ip.G_r = inp.G_r
	ip.EncKey = inp.EncKey

	// ========== 2) On construit le Circuit complet ==========
	circuitFull, err := ip.BuildWitness()
	if err != nil {
		return nil, nil, zg.InputProverRegister{}, fmt.Errorf("build witness: %w", err)
	}

	// ========== 3) On crée le witness Gnark (privé+public) ==========
	w, err := frontend.NewWitness(circuitFull, ecc.BW6_761.ScalarField())
	if err != nil {
		return nil, nil, zg.InputProverRegister{}, fmt.Errorf("NewWitness: %w", err)
	}

	// ========== 4) On récupère le witness public pour le verifieur ==========
	wPub, err := w.Public()
	if err != nil {
		return nil, nil, zg.InputProverRegister{}, fmt.Errorf("w.Public: %w", err)
	}
	var pubBuf bytes.Buffer
	if _, err = wPub.WriteTo(&pubBuf); err != nil {
		return nil, nil, zg.InputProverRegister{}, fmt.Errorf("wPub.WriteTo: %w", err)
	}

	// ========== 5) Génération de la preuve ZK ==========
	proof, err := groth16.Prove(ccsRegister, pkRegister, w)
	if err != nil {
		return nil, nil, zg.InputProverRegister{}, fmt.Errorf("groth16.Prove: %w", err)
	}
	var proofBuf bytes.Buffer
	if _, err := proof.WriteTo(&proofBuf); err != nil {
		return nil, nil, zg.InputProverRegister{}, fmt.Errorf("proof.WriteTo: %w", err)
	}

	// On renvoie (preuve sérialisée, witness public sérialisé)
	return proofBuf.Bytes(), pubBuf.Bytes(), ip, nil
}

// func ProofRegister(
// 	inp zg.TxProverInputHighLevelRegister,
// 	ccsRegister constraint.ConstraintSystem,
// 	pkRegister groth16.ProvingKey,
// ) (proofBytes []byte, publicWitnessBytes []byte, err error) {

// 	// 1) on construit la structure InputProverRegister (décrivant
// 	//    le circuit Register) à partir de inp
// 	var ip zg.InputProverRegister

// 	ip.InCoin = inp.InCoin
// 	ip.InEnergy = inp.InEnergy
// 	ip.CmIn = inp.CmIn
// 	ip.SkIn = inp.SkIn
// 	ip.PkIn = inp.PkIn
// 	ip.PkOut = inp.PkOut
// 	ip.GammaInEnergy = inp.InVal.Energy
// 	ip.GammaInCoins = inp.InVal.Coins
// 	ip.Bid = inp.Bid

// 	// Copie des 5 blocs chiffrés dans le circuit
// 	for i := 0; i < 5; i++ {
// 		ip.CAux[i] = inp.CAux[i]
// 	}

// 	ip.RhoIn = inp.RhoIn
// 	ip.RandIn = inp.RandIn

// 	// Paramètres liés au Diffie-Hellman pour le chiffrement
// 	ip.R = inp.R
// 	ip.G = inp.G
// 	ip.G_b = inp.G_b
// 	ip.G_r = inp.G_r
// 	ip.EncKey = inp.EncKey

// 	// 2) Construction du witness complet (privé + public)
// 	witnessFull, err := ip.BuildWitness()
// 	if err != nil {
// 		return nil, nil, fmt.Errorf("BuildWitness failed: %w", err)
// 	}
// 	w, err := frontend.NewWitness(witnessFull, ecc.BW6_761.ScalarField())
// 	if err != nil {
// 		return nil, nil, fmt.Errorf("NewWitness failed: %w", err)
// 	}

// 	// 3) On récupère le *witness* public, pour pouvoir faire le Verify côté réception
// 	wPub, err := w.Public()
// 	if err != nil {
// 		return nil, nil, fmt.Errorf("w.Public() failed: %w", err)
// 	}
// 	var pubBuf bytes.Buffer
// 	if _, err := wPub.WriteTo(&pubBuf); err != nil {
// 		return nil, nil, fmt.Errorf("writing public witness to buffer: %w", err)
// 	}

// 	// 4) Génération de la preuve
// 	proof, err := groth16.Prove(ccsRegister, pkRegister, w)
// 	if err != nil {
// 		return nil, nil, fmt.Errorf("groth16.Prove failed: %w", err)
// 	}

// 	// 5) Sérialisation de la preuve dans un buffer
// 	var proofBuf bytes.Buffer
// 	if _, err := proof.WriteTo(&proofBuf); err != nil {
// 		return nil, nil, fmt.Errorf("proof.WriteTo failed: %w", err)
// 	}

// 	return proofBuf.Bytes(), pubBuf.Bytes(), nil
// }

func ProofRegisterOld(inp zg.TxProverInputHighLevelRegister, globalCCSRegister constraint.ConstraintSystem, globalPKRegister groth16.ProvingKey, conn net.Conn, ID int, targetAddress string, targetID int) []byte {
	// // 1) snOld[i] = MiMC(skOld[i], RhoOld[i]) off-circuit
	// var snOld []byte
	// sn := zg.CalcSerialMimc(inp.OldSk, inp.OldNote.Rho)
	// snOld = sn
	// // 2) Generate (rhoNew, randNew), cmNew, cNew
	// var rhoNew *big.Int
	// var randNew *big.Int
	// var cmNew []byte
	// //var cNew [2][][]byte
	// var cNew zg.Note

	// rhoNew = zg.RandBigInt()
	// randNew = zg.RandBigInt()
	// cm := zg.Committment(inp.NewVal.Coins, inp.NewVal.Energy,
	// 	rhoNew, randNew)
	// cmNew = cm
	// encVal := zg.BuildEncMimc(inp.EncKey, inp.NewPk,
	// 	inp.NewVal.Coins, inp.NewVal.Energy,
	// 	rhoNew, randNew, cm)

	// // get pk_enc
	// pk_enc := encVal[0].Bytes()
	// pk_enc_bytes := make([]byte, len(pk_enc))
	// copy(pk_enc_bytes, pk_enc[:])
	// cNew.PkOwner = pk_enc_bytes

	// // get coins_enc
	// coins_enc := encVal[1].Bytes()
	// coins_enc_bytes := make([]byte, len(coins_enc))
	// copy(coins_enc_bytes, coins_enc[:])
	// cNew.Value.Coins = new(big.Int).SetBytes(coins_enc_bytes)

	// // get energy_enc
	// energy_enc := encVal[2].Bytes()
	// energy_enc_bytes := make([]byte, len(energy_enc))
	// copy(energy_enc_bytes, energy_enc[:])
	// cNew.Value.Energy = new(big.Int).SetBytes(energy_enc_bytes)

	// // get rho_enc
	// rho_enc := encVal[3].Bytes()
	// rho_enc_bytes := make([]byte, len(rho_enc))
	// copy(rho_enc_bytes, rho_enc[:])
	// cNew.Rho = rho_enc_bytes

	// // get rand_enc
	// rand_enc := encVal[4].Bytes()
	// rand_enc_bytes := make([]byte, len(rand_enc))
	// copy(rand_enc_bytes, rand_enc[:])
	// cNew.Rand = rand_enc_bytes

	// // get cm_enc
	// cm_enc := encVal[5].Bytes()
	// cm_enc_bytes := make([]byte, len(cm_enc))
	// copy(cm_enc_bytes, cm_enc[:])
	// cNew.Cm = cm_enc_bytes

	// 3) Build InputProver
	var ip zg.InputProverRegister

	ip.InCoin = new(big.Int).SetBytes(inp.InCoin)
	ip.InEnergy = new(big.Int).SetBytes(inp.InEnergy)
	ip.CmIn = inp.CmIn
	ip.SkIn = new(big.Int).SetBytes(inp.SkIn)
	ip.PkIn = new(big.Int).SetBytes(inp.PkIn)
	ip.PkOut = new(big.Int).SetBytes(inp.PkOut)
	ip.GammaInEnergy = inp.InVal.Energy
	ip.GammaInCoins = inp.InVal.Coins

	ip.Bid = new(big.Int).SetBytes(inp.Bid)

	for i := 0; i < 5; i++ {
		ip.CAux[i] = inp.CAux[i]
	}

	//ip.CAux = inp.CAux

	ip.RhoIn = new(big.Int).SetBytes(inp.RhoIn)
	ip.RandIn = new(big.Int).SetBytes(inp.RandIn)

	ip.R = new(big.Int).SetBytes(inp.R)
	//ip.B = inp.B
	ip.G = inp.G
	ip.G_b = inp.G_b
	ip.G_r = inp.G_r
	ip.EncKey = inp.EncKey

	wc, _ := ip.BuildWitness()
	w, _ := frontend.NewWitness(wc, ecc.BW6_761.ScalarField())

	// 4) Generate proof
	_ = time.Now()
	proof, err := groth16.Prove(globalCCSRegister, globalPKRegister, w)
	if err != nil {
		panic(err)
	}

	var buf bytes.Buffer
	proof.WriteTo(&buf)

	/*

		TxResult:      txResult,
		Old:           inp.OldNote,
		NewVal:        inp.NewVal,
		ID:            ID,
		TargetAddress: targetAddress,
		TargetID:      targetID,*/

	return buf.Bytes()
}

// RelayMessage relays a message (outside the Diffie–Hellman protocol).
func (n *Node) RelayMessage(fromAddress string, targetAddress string, message string) error {
	relayMsg := fmt.Sprintf("Relayed from %s to %s: %s", fromAddress, targetAddress, message)
	return n.SendMessage(targetAddress, zn.PackMessage("relay", relayMsg))
}

// -------------------------------
// TxDefaultOneCoin Handler
// -------------------------------
// type TxDefaultOneCoinHandler struct {
// 	Node *Node // Pointer to the parent node
// }

// func NewTxDefaultOneCoinHandler(node *Node) *TxDefaultOneCoinHandler {
// 	return &TxDefaultOneCoinHandler{
// 		Node: node,
// 	}
// }

// // HandleMessage processes a "DiffieHellman" type message received by the verifier.
// // When it receives "DH_G_r", it stores A (the initiator's ephemeral key),
// // generates its ephemeral secret b, computes B = G^b, computes the shared secret S = A^b,
// // and sends back a "DH_G_b" message containing B.
// func (dh *TxDefaultOneCoinHandler) HandleMessage(msg zn.Message, conn net.Conn) {
// 	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()
// 	remoteAddr := conn.RemoteAddr().String()
// 	payload, ok := msg.Payload.(zn.TxDefaultOneCoinPayload)
// 	if !ok {
// 		fmt.Printf("TxDefaultOneCoinHandler Handler (node %d): Non-conforming payload from %s", dh.Node.ID, remoteAddr)
// 		return
// 	}

// 	//ICI

// 	if payload.SubType == "DH_G_r" {
// 		// Store A received from the initiator in DHExchanges with key = payload.ID.
// 		dh.Node.DHExchanges[payload.ID] = &zn.DHParams{
// 			EphemeralPublic: payload.Value,
// 		}
// 		logger.Info().Msg(fmt.Sprintf("%s[Node %d] [Diffie-Hellman] Received DH_G_r from node %d\033[0m", getNodeColor(dh.Node.ID), dh.Node.ID, payload.ID))
// 		//fmt.Printf("DiffieHellman Handler (node %d): Received DH_G_r from node %d : %+v\n", dh.Node.ID, payload.ID, payload.Value)

// 		// Generate ephemeral secret b and compute B = G^b.
// 		b, _ := zg.GenerateBls12377_frElement()
// 		secret := b.Bytes() // verifier's secret
// 		B := *new(bls12377.G1Affine).ScalarMultiplication(&dh.Node.G, new(big.Int).SetBytes(secret[:]))
// 		// Compute the shared secret S = A^b.
// 		A := dh.Node.DHExchanges[payload.ID].EphemeralPublic
// 		shared := *new(bls12377.G1Affine).ScalarMultiplication(&A, new(big.Int).SetBytes(secret[:]))
// 		// Store these values in DHExchanges for this peer.
// 		dh.Node.DHExchanges[payload.ID] = &zn.DHParams{
// 			EphemeralPublic: payload.Value, // A received from the initiator
// 			PartnerPublic:   B,             // B computed by the verifier
// 			Secret:          secret[:],
// 			SharedSecret:    shared,
// 		}

// 		//fmt.Printf("DiffieHellman Handler (node %d): Shared secret computed: %+v\n", dh.Node.ID, shared)
// 		logger.Info().Msg(fmt.Sprintf("%s[Node %d] [Diffie-Hellman] Shared secret computed\033[0m", getNodeColor(dh.Node.ID), dh.Node.ID))

// 		// Send the "DH_G_b" message containing B.
// 		respPayload := zn.DHPayload{
// 			ID:      dh.Node.ID,
// 			SubType: "DH_G_b",
// 			Value:   B,
// 		}
// 		respMsg := zn.PackMessage("DiffieHellman", respPayload)
// 		if err := zn.SendMessage(conn, respMsg); err != nil {
// 			logger.Error().Err(err).Msg(fmt.Sprintf("%s[Node %d] [Diffie-Hellman] Error sending DH_G_b to node %d\033[0m", getNodeColor(dh.Node.ID), dh.Node.ID, payload.ID))
// 			//fmt.Printf("DiffieHellman Handler (node %d): Error sending DH_G_b to node %d: %v\n", dh.Node.ID, payload.ID, err)
// 		} else {
// 			logger.Info().Msg(fmt.Sprintf("%s[Node %d] [Diffie-Hellman] DH_G_b sent to node %d\033[0m", getNodeColor(dh.Node.ID), dh.Node.ID, payload.ID))
// 			//fmt.Printf("DiffieHellman Handler (node %d): DH_G_b sent to node %d\n", dh.Node.ID, payload.ID)
// 		}
// 	} else {
// 		logger.Error().Msg(fmt.Sprintf("%s[Node %d] [Diffie-Hellman] Unknown subtype '%s' from node %d\033[0m", getNodeColor(dh.Node.ID), dh.Node.ID, payload.SubType, payload.ID))
// 		//fmt.Printf("DiffieHellman Handler (node %d): Unknown subtype '%s' from node %d\n", dh.Node.ID, payload.SubType, payload.ID)
// 	}
// }

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
			EphemeralPublic: B,             //payload.Value, // A received from the initiator
			PartnerPublic:   payload.Value, //B,             // B computed by the verifier
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
// func (th *TransactionHandler) HandleMessage(msg zn.Message, conn net.Conn) {
// 	//tx, ok := msg.Payload.(zg.TxResult)
// 	tx, ok := msg.Payload.(zn.Tx)
// 	if !ok {
// 		fmt.Println("TransactionHandler: invalid payload")
// 		return
// 	}
// 	// Process the transaction as needed.
// 	fmt.Printf("%s[Node %d] [Transaction] Transaction received: %+v\033[0m\n", getNodeColor(th.Node.ID), th.Node.ID, tx)

// 	ID := tx.ID

// 	ok = zg.ValidateTx(tx.TxResult,
// 		tx.Old,
// 		tx.NewVal,
// 		th.Node.G,
// 		th.Node.DHExchanges[ID].PartnerPublic,
// 		th.Node.DHExchanges[ID].EphemeralPublic)

// 	fmt.Println("result: ", ok)

// 	//Get shared secret

//		// ok := zg.ValidateTx(tx,
//		// 	[2]Note{old1, old2},
//		// 	[2]Gamma{new1, new2},
//		// 	tx
//		// )
//	}
func (th *TransactionHandler) HandleMessage(msg zn.Message, conn net.Conn) {
	//tx, ok := msg.Payload.(zg.TxResult)

	//tx, ok := msg.Payload.(zn.Tx)

	tx, ok := msg.Payload.(zn.TxEncapsulated)
	if !ok {
		fmt.Println("TransactionHandler: invalid payload")
		return
	}
	// Process the transaction as needed.
	fmt.Printf("%s[Node %d] [Transaction] Transaction received: %+v\033[0m\n", getNodeColor(th.Node.ID), th.Node.ID, tx)

	if tx.Kind == 0 {
		txPayload, ok := tx.Payload.(zn.Tx)
		if !ok {
			fmt.Println("TransactionHandler: invalid payload")
			return
		}
		//tx = txPayload
		ID := txPayload.ID

		ok = zg.ValidateTx(txPayload.TxResult,
			txPayload.Old,
			txPayload.NewVal,
			th.Node.G,
			th.Node.DHExchanges[ID].PartnerPublic,
			th.Node.DHExchanges[ID].EphemeralPublic,
			globalVK)
	} else {
		//tx = tx.payload.(zn.TxDefaultOneCoinPayload)
		txPayload, ok := tx.Payload.(zn.TxDefaultOneCoinPayload)
		if !ok {
			fmt.Println("TransactionHandler: invalid payload")
			return
		}
		ID := txPayload.ID

		ok = zg.ValidateTxDefaultCoin(txPayload.TxResult,
			txPayload.Old,
			txPayload.NewVal,
			th.Node.G,
			th.Node.DHExchanges[ID].PartnerPublic,
			th.Node.DHExchanges[ID].EphemeralPublic,
			globalVKOneCoin)
	}

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
	tx, ok := msg.Payload.(zn.TxEncapsulated)
	if !ok {
		fmt.Println("TransactionValidatorHandler: invalid payload")
		return
	}

	fmt.Println("TransactionValidatorHandler")

	// Validate the transaction
	// valid := zg.ValidateTx(tx.TxResult, tx.Old, tx.NewVal, tvh.Node.G, tvh.Node.DHExchanges[tx.ID].PartnerPublic, tvh.Node.DHExchanges[tx.ID].EphemeralPublic)

	if tx.Kind == 0 {
		txPayload, _ := tx.Payload.(zn.Tx)
		// Open a connection to the recipient to retrieve its DH parameters
		destConn, err := net.Dial("tcp", txPayload.TargetAddress)
		if err != nil {
			fmt.Printf("%s[Node %d] [Validator] Error dialing destination %s: %v\033[0m\n", getNodeColor(tvh.Node.ID), tvh.Node.ID, txPayload.TargetAddress, err)
			return
		}
		defer destConn.Close()

		// Send a DH request
		reqPayload := zn.DHRequestPayload{SenderID: txPayload.ID}
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

		// Validate the proof using the parameters retrieved from the recipient
		valid_0 := zg.ValidateTx(txPayload.TxResult, txPayload.Old, txPayload.NewVal, tvh.Node.G, respPayload.DestPartnerPublic, respPayload.DestEphemeralPublic, globalVK)

		//Ensure spending numbers are not already in SnList
		valid_1 := !containsByteSlice(SnList, txPayload.TxResult.SnOld[0]) || containsByteSlice(SnList, txPayload.TxResult.SnOld[1])

		if valid_0 && valid_1 {
			logger.Info().Msg(fmt.Sprintf("%s[Node %d] [Validator] Transaction validated.\033[0m", getNodeColor(tvh.Node.ID), tvh.Node.ID))
			// Add the serial numbers to the list
			SnList = append(SnList, txPayload.TxResult.SnOld[0])
			SnList = append(SnList, txPayload.TxResult.SnOld[1])
			// Add the transaction to the list
			TxList = append(TxList, txPayload.TxResult)
			// Add committments to the list
			CmList = append(CmList, txPayload.TxResult.CmNew[0])
			CmList = append(CmList, txPayload.TxResult.CmNew[1])

		} else {
			logger.Info().Msg(fmt.Sprintf("%s[Node %d] [Validator] Transaction invalid.\033[0m", getNodeColor(tvh.Node.ID), tvh.Node.ID))
		}
	} else {
		txPayload, _ := tx.Payload.(zn.TxDefaultOneCoinPayload)
		// Open a connection to the recipient to retrieve its DH parameters
		destConn, err := net.Dial("tcp", txPayload.TargetAddress)
		if err != nil {
			fmt.Printf("%s[Node %d] [Validator] Error dialing destination %s: %v\033[0m\n", getNodeColor(tvh.Node.ID), tvh.Node.ID, txPayload.TargetAddress, err)
			return
		}
		defer destConn.Close()

		// Send a DH request
		reqPayload := zn.DHRequestPayload{SenderID: txPayload.ID}
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
		valid_0 := zg.ValidateTxDefaultCoin(txPayload.TxResult, txPayload.Old, txPayload.NewVal, tvh.Node.G, respPayload.DestPartnerPublic, respPayload.DestEphemeralPublic, globalVKOneCoin)

		//Ensure spending numbers are not already in SnList
		valid_1 := !containsByteSlice(SnList, txPayload.TxResult.SnOld)

		if valid_0 && valid_1 {
			logger.Info().Msg(fmt.Sprintf("%s[Node %d] [Validator] Transaction validated.\033[0m", getNodeColor(tvh.Node.ID), tvh.Node.ID))
			// Add the serial numbers to the list
			SnList = append(SnList, txPayload.TxResult.SnOld)
			// Add the transaction to the list
			TxListDefaultOneCoin = append(TxListDefaultOneCoin, txPayload.TxResult)
			// Add committments to the list
			CmList = append(CmList, txPayload.TxResult.CmNew)
		} else {
			logger.Info().Msg(fmt.Sprintf("%s[Node %d] [Validator] Transaction invalid.\033[0m", getNodeColor(tvh.Node.ID), tvh.Node.ID))
		}
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
// AuctionHandler
// -------------------------------

type AuctionHandler struct {
	Node *Node
}

func NewAuctionHandler(node *Node) *AuctionHandler {
	return &AuctionHandler{Node: node}
}

func ExtractEncryptedCoins(inp_ *zg.TxProverInputHighLevelFN, coinCount int) [][5][]byte {
	coinsEnc := make([][5][]byte, coinCount)
	for i := 0; i < coinCount; i++ {
		var coin [5][]byte
		for j := 0; j < 5; j++ {
			data := inp_.C[i][j].Bytes()
			copyData := make([]byte, len(data))
			copy(copyData, data[:])
			coin[j] = copyData
		}
		coinsEnc[i] = coin
	}
	return coinsEnc
}

func (drh *AuctionHandler) HandleMessage(msg zn.Message, conn net.Conn) {
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()
	// Example implementation:
	// Extract the payload of type DHRequestPayload (which you must define)
	req, ok := msg.Payload.(zn.AuctionResultN)
	if !ok {
		fmt.Println("AuctionHandler: invalid payload")
		return
	}
	logger.Info().Msg(fmt.Sprintf("%s[Node %d] [Auction] Received an auction result from sender %d\033[0m", getNodeColor(drh.Node.ID), drh.Node.ID, req.SenderID))

	/////////////

	N := len(req.InpDOC.OldSk)
	coinCount := N

	inp := req.InpDOC
	rhoNewList := req.RhoNew
	randNewList := req.RandNew

	// 1) Calculer snOld pour chaque coin
	var snOldList [][]byte
	for i := 0; i < coinCount; i++ {
		sn := zg.CalcSerialMimc(inp.OldSk[i], inp.OldNote[i].Rho)
		snOldList = append(snOldList, sn)
	}

	// 2) Pour chaque coin, générer (rhoNew, randNew), cmNew et cNew
	var cmNewList [][]byte
	var cNewList []zg.Note
	// Chaque élément de encValList est un tableau de 6 éléments (valeurs encryptées)
	var encValList [][6]bls12377_fp.Element

	for i := 0; i < coinCount; i++ {
		// Calcul du commitment pour le nouveau coin
		cm := zg.Committment(inp.NewVal[i].Coins, inp.NewVal[i].Energy,
			rhoNewList[i], randNewList[i])
		cmNewList = append(cmNewList, cm)

		// Calcul des valeurs encryptées
		encVal := zg.BuildEncMimc(inp.EncKey[i], inp.NewPk[i],
			inp.NewVal[i].Coins, inp.NewVal[i].Energy,
			rhoNewList[i], randNewList[i], cm)
		encValList = append(encValList, encVal)

		// Construction de la nouvelle note (cNew)
		var note zg.Note

		// Extraction de pk_enc
		pk_enc := encVal[0].Bytes()
		pk_enc_bytes := make([]byte, len(pk_enc))
		copy(pk_enc_bytes, pk_enc[:])
		note.PkOwner = pk_enc_bytes

		// Extraction de coins_enc
		coins_enc := encVal[1].Bytes()
		coins_enc_bytes := make([]byte, len(coins_enc))
		copy(coins_enc_bytes, coins_enc[:])
		note.Value.Coins = new(big.Int).SetBytes(coins_enc_bytes)

		// Extraction de energy_enc
		energy_enc := encVal[2].Bytes()
		energy_enc_bytes := make([]byte, len(energy_enc))
		copy(energy_enc_bytes, energy_enc[:])
		note.Value.Energy = new(big.Int).SetBytes(energy_enc_bytes)

		// Extraction de rho_enc
		rho_enc := encVal[3].Bytes()
		rho_enc_bytes := make([]byte, len(rho_enc))
		copy(rho_enc_bytes, rho_enc[:])
		note.Rho = rho_enc_bytes

		// Extraction de rand_enc
		rand_enc := encVal[4].Bytes()
		rand_enc_bytes := make([]byte, len(rand_enc))
		copy(rand_enc_bytes, rand_enc[:])
		note.Rand = rand_enc_bytes

		// Extraction de cm_enc
		cm_enc := encVal[5].Bytes()
		cm_enc_bytes := make([]byte, len(cm_enc))
		copy(cm_enc_bytes, cm_enc[:])
		note.Cm = cm_enc_bytes

		cNewList = append(cNewList, note)
	}

	// 3) Construire l'InputProver pour N coins
	var ip zg.InputProverDefaultNCoin

	// Partie "old" (chaque champ est une slice)
	ip.OldCoin = make([]*big.Int, coinCount)
	ip.OldEnergy = make([]*big.Int, coinCount)
	ip.CmOld = make([][]byte, coinCount)
	ip.SnOld = make([][]byte, coinCount)
	ip.PkOld = make([][]byte, coinCount)
	ip.SkOld = make([]*big.Int, coinCount)
	ip.RhoOld = make([]*big.Int, coinCount)
	ip.RandOld = make([]*big.Int, coinCount)

	for i := 0; i < coinCount; i++ {
		ip.OldCoin[i] = inp.OldNote[i].Value.Coins
		ip.OldEnergy[i] = inp.OldNote[i].Value.Energy
		ip.CmOld[i] = inp.OldNote[i].Cm
		ip.SnOld[i] = snOldList[i]
		ip.PkOld[i] = inp.OldNote[i].PkOwner
		ip.SkOld[i] = new(big.Int).SetBytes(inp.OldSk[i])
		ip.RhoOld[i] = new(big.Int).SetBytes(inp.OldNote[i].Rho)
		ip.RandOld[i] = new(big.Int).SetBytes(inp.OldNote[i].Rand)
	}

	// Partie "new" (chaque champ est une slice)
	ip.NewCoin = make([]*big.Int, coinCount)
	ip.NewEnergy = make([]*big.Int, coinCount)
	ip.CmNew = make([][]byte, coinCount)
	// CNew est une slice de slices : pour chaque coin, 6 éléments comme dans TransactionOneCoin
	ip.CNew = make([][][]byte, coinCount)
	ip.R = make([][]byte, coinCount)
	ip.G = make([]bls12377.G1Affine, coinCount)
	ip.G_b = make([]bls12377.G1Affine, coinCount)
	ip.G_r = make([]bls12377.G1Affine, coinCount)
	ip.EncKey = make([]bls12377.G1Affine, coinCount)

	for i := 0; i < coinCount; i++ {
		ip.NewCoin[i] = inp.NewVal[i].Coins
		ip.NewEnergy[i] = inp.NewVal[i].Energy
		ip.CmNew[i] = cmNewList[i]

		coinCNew := make([][]byte, 6)
		coinCNew[0] = cNewList[i].PkOwner
		coinCNew[1] = cNewList[i].Value.Coins.Bytes()
		coinCNew[2] = cNewList[i].Value.Energy.Bytes()
		coinCNew[3] = cNewList[i].Rho
		coinCNew[4] = cNewList[i].Rand
		coinCNew[5] = cNewList[i].Cm
		ip.CNew[i] = coinCNew

		// Les autres paramètres globaux restent inchangés
		ip.R[i] = inp.R[i]
		ip.G[i] = inp.G[i]
		ip.G_b[i] = inp.G_b[i]
		ip.G_r[i] = inp.G_r[i]
		ip.EncKey[i] = inp.EncKey[i]
	}

	// Pour les clés publiques new (une par coin)
	ip.PkNew = make([]*big.Int, coinCount)
	for i := 0; i < coinCount; i++ {
		ip.PkNew[i] = new(big.Int).SetBytes(inp.NewPk[i])
	}
	ip.RhoNew = rhoNewList
	ip.RandNew = randNewList

	// //error if N!=2
	// if N != 2 {
	// 	panic("N must be 2")
	// }

	var wc frontend.Circuit

	switch N {
	case 2:
		wc, _ = ip.BuildWitness2()
	case 3:
		wc, _ = ip.BuildWitness3()
	}

	// Construction du witness
	//wc, _ := ip.BuildWitness2()
	w, _ := frontend.NewWitness(wc, ecc.BW6_761.ScalarField(), frontend.PublicOnly())

	wPub, _ := w.Public()
	var pubBuf bytes.Buffer
	if _, err := wPub.WriteTo(&pubBuf); err != nil {
		panic(err)
	}

	buf := bytes.NewReader(req.TxOut.TxResult.Proof)
	p := groth16.NewProof(ecc.BW6_761)
	_, err := p.ReadFrom(buf)
	if err != nil {
		fmt.Println("invalid proof =>", err)
	}
	switch N {
	case 2:
		err = groth16.Verify(p, globalVK2Coin, w)
		if err != nil {
			fmt.Println("Verify fail =>", err)
		}
	case 3:
		err = groth16.Verify(p, globalVK3Coin, w)
		if err != nil {
			fmt.Println("Verify fail =>", err)
		}
	}

	/////////////

	/////////////

	inp_ := req.InpF

	//coinCount := len(inp.InCoin)
	var inCoinConv, inEnergyConv, inCmConv, inSnConv, inPkConv, inSkConv, inRhoConv, inRandConv []frontend.Variable
	var outCoinConv, outEnergyConv, outCmConv, outSnConv, outPkConv, outRhoConv, outRandConv []frontend.Variable
	var RConv []frontend.Variable

	for i := 0; i < coinCount; i++ {
		inCoinConv = append(inCoinConv, new(big.Int).SetBytes(inp_.InCoin[i]))
		inEnergyConv = append(inEnergyConv, new(big.Int).SetBytes(inp_.InEnergy[i]))
		inCmConv = append(inCmConv, new(big.Int).SetBytes(inp_.InCm[i]))
		inSnConv = append(inSnConv, new(big.Int).SetBytes(inp_.InSn[i]))
		inPkConv = append(inPkConv, new(big.Int).SetBytes(inp_.InPk[i]))
		inSkConv = append(inSkConv, new(big.Int).SetBytes(inp_.InSk[i]))
		inRhoConv = append(inRhoConv, new(big.Int).SetBytes(inp_.InRho[i]))
		inRandConv = append(inRandConv, new(big.Int).SetBytes(inp_.InRand[i]))

		outCoinConv = append(outCoinConv, new(big.Int).SetBytes(inp_.OutCoin[i]))
		outEnergyConv = append(outEnergyConv, new(big.Int).SetBytes(inp_.OutEnergy[i]))
		outCmConv = append(outCmConv, new(big.Int).SetBytes(inp_.OutCm[i]))
		outSnConv = append(outSnConv, new(big.Int).SetBytes(inp_.OutSn[i]))
		outPkConv = append(outPkConv, new(big.Int).SetBytes(inp_.OutPk[i]))
		outRhoConv = append(outRhoConv, new(big.Int).SetBytes(inp_.OutRho[i]))
		outRandConv = append(outRandConv, new(big.Int).SetBytes(inp_.OutRand[i]))

		RConv = append(RConv, new(big.Int).SetBytes(inp_.R[i])) //NOT GOOD
	}

	coinsEnc := ExtractEncryptedCoins(&inp_, coinCount)

	// // --- Extraction des éléments chiffrés pour le coin 0 ---
	// pk_enc0 := inp_.C[0][0].Bytes()
	// pk_enc0_bytes := make([]byte, len(pk_enc0))
	// copy(pk_enc0_bytes, pk_enc0[:])

	// coins_enc0 := inp_.C[0][3].Bytes()
	// coins_enc0_bytes := make([]byte, len(coins_enc0))
	// copy(coins_enc0_bytes, coins_enc0[:])

	// energy_enc0 := inp_.C[0][4].Bytes()
	// energy_enc0_bytes := make([]byte, len(energy_enc0))
	// copy(energy_enc0_bytes, energy_enc0[:])

	// skIn_enc0 := inp_.C[0][1].Bytes()
	// skIn_enc0_bytes := make([]byte, len(skIn_enc0))
	// copy(skIn_enc0_bytes, skIn_enc0[:])

	// bid_enc0 := inp_.C[0][2].Bytes()
	// bid_enc0_bytes := make([]byte, len(bid_enc0))
	// copy(bid_enc0_bytes, bid_enc0[:])

	// // --- Extraction des éléments chiffrés pour le coin 1 ---
	// pk_enc1 := inp_.C[1][0].Bytes()
	// pk_enc1_bytes := make([]byte, len(pk_enc1))
	// copy(pk_enc1_bytes, pk_enc1[:])

	// coins_enc1 := inp_.C[1][3].Bytes()
	// coins_enc1_bytes := make([]byte, len(coins_enc1))
	// copy(coins_enc1_bytes, coins_enc1[:])

	// energy_enc1 := inp_.C[1][4].Bytes()
	// energy_enc1_bytes := make([]byte, len(energy_enc1))
	// copy(energy_enc1_bytes, energy_enc1[:])

	// skIn_enc1 := inp_.C[1][1].Bytes()
	// skIn_enc1_bytes := make([]byte, len(skIn_enc1))
	// copy(skIn_enc1_bytes, skIn_enc1[:])

	// bid_enc1 := inp_.C[1][2].Bytes()
	// bid_enc1_bytes := make([]byte, len(bid_enc1))
	// copy(bid_enc1_bytes, bid_enc1[:])

	// // Constitution des tableaux d'encryption pour chaque coin.
	// var C0 [5][]byte = [5][]byte{
	// 	pk_enc0_bytes,
	// 	skIn_enc0_bytes,
	// 	bid_enc0_bytes,
	// 	coins_enc0_bytes,
	// 	energy_enc0_bytes,
	// }
	// var C1 [5][]byte = [5][]byte{
	// 	pk_enc1_bytes,
	// 	skIn_enc1_bytes,
	// 	bid_enc1_bytes,
	// 	coins_enc1_bytes,
	// 	energy_enc1_bytes,
	// }

	// Construction de l'input pour le circuit multi‑coin (N=2)
	ip_ := zg.InputTxFN{
		InCoin:    inCoinConv,
		InEnergy:  inEnergyConv,
		InCm:      inCmConv,
		InSn:      inSnConv,
		InPk:      inPkConv,
		InSk:      inSkConv,
		InRho:     inRhoConv,
		InRand:    inRandConv,
		OutCoin:   outCoinConv,
		OutEnergy: outEnergyConv,
		OutCm:     outCmConv,
		OutSn:     outSnConv,
		OutPk:     outPkConv,
		OutRho:    outRhoConv,
		OutRand:   outRandConv,
		// Pour le champ C, on construit un slice contenant les tableaux pour chaque coin.
		C:      coinsEnc,    //[][5][]byte{C0, C1},
		DecVal: inp_.DecVal, // On suppose que inp_.DecVal est déjà un slice avec 2 éléments.
		// Paramètres globaux
		SkT:    inp_.SkT,
		EncKey: inp_.EncKey,
		R:      RConv, //new(big.Int).SetBytes(inp_.R), // On suppose que inp_.R est un slice (ex. avec la valeur globale en première position).
		G:      inp_.G,
		G_b:    inp_.G_b,
		G_r:    inp_.G_r,
	}

	// Construction du witness via la méthode BuildWitness de InputTxFN.
	var c frontend.Circuit
	var e error
	switch coinCount {
	case 2:
		c, e = ip_.BuildWitness2()
		if e != nil {
			panic(err)
		}
	case 3:
		c, e = ip_.BuildWitness3()
		if e != nil {
			panic(err)
		}
	}

	w, _ = frontend.NewWitness(c, ecc.BW6_761.ScalarField(), frontend.PublicOnly())

	wPub, _ = w.Public()
	var pubBuf_ bytes.Buffer
	if _, err := wPub.WriteTo(&pubBuf_); err != nil {
		panic(err)
	}

	buf = bytes.NewReader(req.TxFN.Proof)
	p = groth16.NewProof(ecc.BW6_761)
	_, err = p.ReadFrom(buf)
	if err != nil {
		fmt.Println("invalid proof =>", err)
	}
	switch coinCount {
	case 2:
		err = groth16.Verify(p, globalVKF2, w)
		if err != nil {
			fmt.Println("Verify fail =>", err)
		}
	case 3:
		err = groth16.Verify(p, globalVKF3, w)
		if err != nil {
			fmt.Println("Verify fail =>", err)
		}
	}

	/////////////

	// // Verify proof

	// var ip zg.InputProverDefaultOneCoin

	// var snOld []byte
	// sn := zg.CalcSerialMimc(req.InpDOC.OldSk, req.InpDOC.OldNote.Rho)
	// snOld = sn

	// var cmNew []byte
	// var cNew zg.Note

	// cm := zg.Committment(req.InpDOC.NewVal.Coins, req.InpDOC.NewVal.Energy,
	// 	req.RhoNew, req.RandNew)
	// cmNew = cm

	// encVal := zg.BuildEncMimc(req.InpDOC.EncKey, req.InpDOC.NewPk,
	// 	req.InpDOC.NewVal.Coins, req.InpDOC.NewVal.Energy,
	// 	req.RhoNew, req.RandNew, cm)

	// //ICI

	// // get pk_enc
	// pk_enc := encVal[0].Bytes()
	// pk_enc_bytes := make([]byte, len(pk_enc))
	// copy(pk_enc_bytes, pk_enc[:])
	// cNew.PkOwner = pk_enc_bytes

	// // get coins_enc
	// coins_enc := encVal[1].Bytes()
	// coins_enc_bytes := make([]byte, len(coins_enc))
	// copy(coins_enc_bytes, coins_enc[:])
	// cNew.Value.Coins = new(big.Int).SetBytes(coins_enc_bytes)

	// // get energy_enc
	// energy_enc := encVal[2].Bytes()
	// energy_enc_bytes := make([]byte, len(energy_enc))
	// copy(energy_enc_bytes, energy_enc[:])
	// cNew.Value.Energy = new(big.Int).SetBytes(energy_enc_bytes)

	// // get rho_enc
	// rho_enc := encVal[3].Bytes()
	// rho_enc_bytes := make([]byte, len(rho_enc))
	// copy(rho_enc_bytes, rho_enc[:])
	// cNew.Rho = rho_enc_bytes

	// // get rand_enc
	// rand_enc := encVal[4].Bytes()
	// rand_enc_bytes := make([]byte, len(rand_enc))
	// copy(rand_enc_bytes, rand_enc[:])
	// cNew.Rand = rand_enc_bytes

	// // get cm_enc
	// cm_enc := encVal[5].Bytes()
	// cm_enc_bytes := make([]byte, len(cm_enc))
	// copy(cm_enc_bytes, cm_enc[:])
	// cNew.Cm = cm_enc_bytes

	// // old
	// ip.OldCoin = req.InpDOC.OldNote.Value.Coins
	// ip.OldEnergy = req.InpDOC.OldNote.Value.Energy
	// ip.CmOld = req.InpDOC.OldNote.Cm
	// ip.SnOld = snOld
	// ip.PkOld = req.InpDOC.OldNote.PkOwner

	// /*
	// 	ip.SkOld = new(big.Int).SetBytes(inp.OldSk)
	// 	ip.RhoOld = new(big.Int).SetBytes(inp.OldNote.Rho)
	// 	ip.RandOld = new(big.Int).SetBytes(inp.OldNote.Rand)
	// 	// new
	// 	ip.NewCoin = inp.NewVal.Coins
	// 	ip.NewEnergy = inp.NewVal.Energy
	// 	ip.CmNew = cmNew
	// */

	// ip.SkOld = new(big.Int).SetBytes(req.InpDOC.OldSk)
	// ip.RhoOld = new(big.Int).SetBytes(req.InpDOC.OldNote.Rho)
	// ip.RandOld = new(big.Int).SetBytes(req.InpDOC.OldNote.Rand)
	// // new
	// ip.NewCoin = req.InpDOC.NewVal.Coins
	// ip.NewEnergy = req.InpDOC.NewVal.Energy
	// ip.CmNew = cmNew

	// ip.CNew = make([][]byte, 6)
	// ip.CNew[0] = cNew.PkOwner
	// ip.CNew[1] = cNew.Value.Coins.Bytes()
	// ip.CNew[2] = cNew.Value.Energy.Bytes()
	// ip.CNew[3] = cNew.Rho
	// ip.CNew[4] = cNew.Rand
	// ip.CNew[5] = cNew.Cm

	// ip.PkNew = new(big.Int).SetBytes(req.InpDOC.NewPk)
	// ip.RhoNew = req.RhoNew
	// ip.RandNew = req.RandNew

	// ip.G = req.InpDOC.G
	// ip.G_b = req.InpDOC.G_b
	// ip.G_r = req.InpDOC.G_r

	// wc, _ := ip.BuildWitness()
	// pubOnly, _ := frontend.NewWitness(wc, ecc.BW6_761.ScalarField(), frontend.PublicOnly())

	// buf := bytes.NewReader(req.TxOut.TxResult.Proof)
	// p := groth16.NewProof(ecc.BW6_761)
	// _, err := p.ReadFrom(buf)
	// if err != nil {
	// 	fmt.Println("invalid proof =>", err)
	// }
	// err = groth16.Verify(p, globalVKOneCoin, pubOnly)
	// if err != nil {
	// 	fmt.Println("Verify fail =>", err)
	// }

	// //var InpDOC zg.TxProverInputHighLevelDefaultOneCoin
	// //var InpF zg.TxProverInputHighLevelF1

	// //InpDOC.OldNote = req.InpDOC.OldNote
	// //InpDOC.NewVal = req.InpDOC.NewVal

	// pk_enc = req.InpF.C[0].Bytes()
	// pk_enc_bytes = make([]byte, len(pk_enc))
	// copy(pk_enc_bytes, pk_enc[:])

	// coins_enc = req.InpF.C[3].Bytes()
	// coins_enc_bytes = make([]byte, len(coins_enc))
	// copy(coins_enc_bytes, coins_enc[:])

	// energy_enc = req.InpF.C[4].Bytes()
	// energy_enc_bytes = make([]byte, len(energy_enc))
	// copy(energy_enc_bytes, energy_enc[:])

	// skIn_enc := req.InpF.C[1].Bytes()
	// skIn_enc_bytes := make([]byte, len(skIn_enc))
	// copy(skIn_enc_bytes, skIn_enc[:])

	// bid_enc := req.InpF.C[2].Bytes()
	// bid_enc_bytes := make([]byte, len(bid_enc))
	// copy(bid_enc_bytes, bid_enc[:])

	// ip_ := zg.InputTxF1{
	// 	InCoin:   new(big.Int).SetBytes(req.InpF.InCoin),
	// 	InEnergy: new(big.Int).SetBytes(req.InpF.InEnergy),
	// 	InCm:     new(big.Int).SetBytes(req.InpF.InCm),
	// 	InSn:     new(big.Int).SetBytes(req.InpF.InSn),
	// 	InPk:     new(big.Int).SetBytes(req.InpF.InPk),
	// 	InSk:     new(big.Int).SetBytes(req.InpF.InSk),
	// 	InRho:    new(big.Int).SetBytes(req.InpF.InRho),
	// 	InRand:   new(big.Int).SetBytes(req.InpF.InRand),

	// 	OutCoin:   new(big.Int).SetBytes(req.InpF.OutCoin),
	// 	OutEnergy: new(big.Int).SetBytes(req.InpF.OutEnergy),
	// 	OutCm:     new(big.Int).SetBytes(req.InpF.OutCm),
	// 	OutSn:     new(big.Int).SetBytes(req.InpF.OutSn),
	// 	OutPk:     new(big.Int).SetBytes(req.InpF.OutPk),
	// 	OutRho:    new(big.Int).SetBytes(req.InpF.OutRho),
	// 	OutRand:   new(big.Int).SetBytes(req.InpF.OutRand),

	// 	SkT: req.InpF.SkT,
	// 	//SnIn:  new(big.Int).SetBytes(inp.SnIn),
	// 	//CmOut: new(big.Int).SetBytes(inp.CmOut),
	// 	//pk_enc_bytes, skIn_enc_bytes, bid_enc_bytes, coins_enc_bytes, energy_enc_bytes},
	// 	C: [5][]byte{
	// 		pk_enc_bytes,
	// 		skIn_enc_bytes,
	// 		bid_enc_bytes,
	// 		coins_enc_bytes,
	// 		energy_enc_bytes,
	// 		// new(big.Int).SetBytes(pk_enc_bytes),
	// 		// new(big.Int).SetBytes(coins_enc_bytes),
	// 		// new(big.Int).SetBytes(energy_enc_bytes),
	// 		// new(big.Int).SetBytes(skIn_enc_bytes),
	// 		// new(big.Int).SetBytes(bid_enc_bytes),
	// 	},
	// 	DecVal: req.InpF.DecVal,
	// 	EncKey: req.InpF.EncKey,

	// 	R:   new(big.Int).SetBytes(req.InpF.R),
	// 	G:   req.InpF.G,
	// 	G_b: req.InpF.G_b,
	// 	G_r: req.InpF.G_r,
	// }

	// c, err := ip_.BuildWitness()
	// if err != nil {
	// 	panic(err)
	// }

	// pubOnly, _ = frontend.NewWitness(c, ecc.BW6_761.ScalarField(), frontend.PublicOnly())

	// buf = bytes.NewReader(req.TxF1.Proof)
	// p = groth16.NewProof(ecc.BW6_761)
	// _, err = p.ReadFrom(buf)
	// if err != nil {
	// 	fmt.Println("invalid proof =>", err)
	// }
	// err = groth16.Verify(p, globalVKF1, pubOnly) // NOT SUITABLE FOR THE PROTOCOL
	// if err != nil {
	// 	fmt.Println("Verify fail =>", err)
	// }

	// req.InpDOC

	// ip.G = G
	// ip.G_b = G_b
	// ip.G_r = G_r

	// wc, _ := ip.BuildWitness()
	// pubOnly, _ := frontend.NewWitness(wc, ecc.BW6_761.ScalarField(), frontend.PublicOnly())

	// buf := bytes.NewReader(tx.Proof)
	// p := groth16.NewProof(ecc.BW6_761)
	// _, err := p.ReadFrom(buf)
	// if err != nil {
	// 	fmt.Println("invalid proof =>", err)
	// 	return false
	// }
	// err = groth16.Verify(p, vk, pubOnly)
	// if err != nil {
	// 	fmt.Println("Verify fail =>", err)
	// 	return false
	// }
	// return true

	// // Retrieve the DH parameters of the recipient (here assumed to be stored in DHExchanges)
	// exchange, exists := drh.Node.DHExchanges[req.SenderID]
	// if !exists {
	// 	fmt.Printf("%s[Node %d] [DH Request] No exchange found for sender %d\033[0m\n", getNodeColor(drh.Node.ID), drh.Node.ID, req.SenderID)
	// 	return
	// }

	// // Build the response with the recipient's info
	// resp := zn.DHResponsePayload{
	// 	DestPartnerPublic:   exchange.PartnerPublic,
	// 	DestEphemeralPublic: exchange.EphemeralPublic,
	// }
	// respMsg := zn.PackMessage("dh_response", resp)
	// if err := zn.SendMessage(conn, respMsg); err != nil {
	// 	logger.Info().Msg(fmt.Sprintf("%s[Node %d] [DH Request] Error sending DH response: %v\033[0m", getNodeColor(drh.Node.ID), drh.Node.ID, err))
	// } else {
	// 	logger.Info().Msg(fmt.Sprintf("%s[Node %d] [DH Request] DH response sent\033[0m", getNodeColor(drh.Node.ID), drh.Node.ID))
	// }
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
// RegisterHandler
// -------------------------------

// RegisterHandler handles "register" messages
type RegisterHandler struct {
	Node *Node
}

// NewRegisterHandler creates a new registration handler.
func NewRegisterHandler(node *Node) *RegisterHandler {
	return &RegisterHandler{Node: node}
}

// HandleMessage processes a "register" message.
// Here you would decode the registration payload and store it.
// func (rh *RegisterHandler) HandleMessage(msg zn.Message, conn net.Conn) {
// 	// For now, simply log that a registration message was received.
// 	rh.Node.logger.Info().Msg(fmt.Sprintf("%s[Node %d] [RegisterHandler] Registration message received from %v\033[0m",
// 		getNodeColor(rh.Node.ID), rh.Node.ID, conn.RemoteAddr()))

//		//TODO
//	}

/*

 */

func (rh *RegisterHandler) HandleMessage(msg zn.Message, conn net.Conn) {
	rh.Node.logger.Info().Msgf("%s[Node %d] [RegisterHandler] 'register' message from %v\033[0m",
		getNodeColor(rh.Node.ID), rh.Node.ID, conn.RemoteAddr())

	// 1) Cast payload
	txReg, ok := msg.Payload.(zn.TxRegister)
	if !ok {
		rh.Node.logger.Warn().Msgf("%s[Node %d] [RegisterHandler] Payload is not TxRegister\033[0m",
			getNodeColor(rh.Node.ID), rh.Node.ID)
		return
	}

	if txReg.TxIn.Kind != 1 {
		rh.Node.logger.Warn().Msgf("%s[Node %d] [RegisterHandler] TxIn.Kind != 1 (expected one-coin)\033[0m",
			getNodeColor(rh.Node.ID), rh.Node.ID)
		return
	}
	txOneCoin, ok := txReg.TxIn.Payload.(zn.TxDefaultOneCoinPayload)
	if !ok {
		rh.Node.logger.Warn().Msgf("%s[Node %d] [RegisterHandler] TxIn.Payload not TxDefaultOneCoinPayload\033[0m",
			getNodeColor(rh.Node.ID), rh.Node.ID)
		return
	}

	// 2) Retrieve ephemeral keys from the transaction's target
	destConn, err := net.Dial("tcp", txOneCoin.TargetAddress)
	if err != nil {
		fmt.Printf("Error dialing target %s: %v\n", txOneCoin.TargetAddress, err)
		return
	}
	defer destConn.Close()

	reqMsg := zn.PackMessage("dh_request", zn.DHRequestPayload{SenderID: txOneCoin.ID})
	if err := zn.SendMessage(destConn, reqMsg); err != nil {
		fmt.Printf("Error sending DH request: %v\n", err)
		return
	}
	var respMsg zn.Message
	if err := zn.ReceiveMessage(destConn, &respMsg); err != nil {
		fmt.Printf("Error receiving DH response: %v\n", err)
		return
	}
	respPayload, ok := respMsg.Payload.(zn.DHResponsePayload)
	if !ok {
		fmt.Println("DH response payload not conforming.")
		return
	}

	// 3) Prepare the arguments to ValidateTxRegister
	//    These must match EXACTLY how you built them in SendTransactionRegister.
	cmIn := /* e.g. */ txReg.CmIn     // if you stored nIn.Cm in txReg
	coinsIn := txOneCoin.NewVal.Coins //big.NewInt(12)                        // if you used 12 in your TxProverInputHighLevelRegister
	fmt.Println("txOneCoin.NewVal.Coins =", txOneCoin.NewVal.Coins)
	energyIn := txOneCoin.NewVal.Energy //big.NewInt(5)                        // if you used 5
	fmt.Println("txOneCoin.NewVal.Energy =", txOneCoin.NewVal.Energy)
	bid := new(big.Int).SetBytes(txReg.AuxCipher[2]) // if the 3rd slot is the plain bid

	/*
		proofBytes []byte, // la preuve
		pubWitnessBytes []byte, // éventuellement le witness public
		// ou alors, si on doit le reconstruire:
		cmIn []byte,
		cAux [5][]byte,
		gammaInCoins, gammaInEnergy, bid *big.Int,
		G, G_b, G_r bls12377.G1Affine,
		vk groth16.VerifyingKey,
	*/

	// 4) Actually call your function
	valid_0 := zg.ValidateTxRegister(
		txReg.PiReg,
		txReg.PubW,
		txReg.Ip,
		cmIn,
		txReg.AuxCipher,
		coinsIn,
		energyIn,
		bid,
		rh.Node.G,
		respPayload.DestPartnerPublic,
		respPayload.DestEphemeralPublic,
		globalVKRegister,
	)

	notDoubleSpent := !containsByteSlice(SnList, txOneCoin.TxResult.SnOld)

	if valid_0 && notDoubleSpent {
		rh.Node.logger.Info().Msgf(
			"%s[Node %d] [RegisterHandler] Register TX validated.\033[0m",
			getNodeColor(rh.Node.ID), rh.Node.ID)
		// Update your local lists
		SnList = append(SnList, txOneCoin.TxResult.SnOld)
		TxListDefaultOneCoin = append(TxListDefaultOneCoin, txOneCoin.TxResult)
		CmListTemp = append(CmListTemp, txOneCoin.TxResult.CmNew)
		TxListTemp = append(TxListTemp, zn.Transaction{Tx: txReg, Id: txOneCoin.ID})
		//
		//var EncVal [5]bl.Element = txOneCoin.EncVal[0:5]
		AuxList = append(AuxList, zn.AuxList{C: txOneCoin.EncVal, Proof: txReg.PiReg, Id: txOneCoin.ID})
		InfoBid = append(InfoBid, zn.InfoBid{Gamma: zg.Gamma{Coins: txReg.Ip.GammaInCoins, Energy: txReg.Ip.GammaInEnergy}, Bid: txReg.Ip.Bid, Kind: txReg.Kind})
	} else {
		rh.Node.logger.Info().Msgf(
			"%s[Node %d] [RegisterHandler] Register TX invalid.\033[0m",
			getNodeColor(rh.Node.ID), rh.Node.ID)
	}
}

// func (rh *RegisterHandler) HandleMessage(msg zn.Message, conn net.Conn) { //TODOGREG!
// 	// 1) On logge qu’on a bien reçu un message "register"
// 	rh.Node.logger.Info().Msg(fmt.Sprintf("%s[Node %d] [RegisterHandler] Registration message received from %v\033[0m",
// 		getNodeColor(rh.Node.ID), rh.Node.ID, conn.RemoteAddr()))

// 	// 2) On essaie de caster le payload en TxRegister
// 	txReg, ok := msg.Payload.(zn.TxRegister)
// 	if !ok {
// 		rh.Node.logger.Warn().Msgf("%s[Node %d] [RegisterHandler] Payload is not a TxRegister\033[0m",
// 			getNodeColor(rh.Node.ID), rh.Node.ID)
// 		return
// 	}

// 	// 3) À l’intérieur de TxRegister, on récupère le TxEncapsulated (TxIn) de type TxDefaultOneCoinPayload
// 	if txReg.TxIn.Kind != 1 {
// 		rh.Node.logger.Warn().Msgf("%s[Node %d] [RegisterHandler] TxIn.Kind is not 1 (one-coin transaction)\033[0m",
// 			getNodeColor(rh.Node.ID), rh.Node.ID)
// 		return
// 	}
// 	txOneCoin, ok := txReg.TxIn.Payload.(zn.TxDefaultOneCoinPayload)
// 	if !ok {
// 		rh.Node.logger.Warn().Msgf("%s[Node %d] [RegisterHandler] TxIn.Payload is not TxDefaultOneCoinPayload\033[0m",
// 			getNodeColor(rh.Node.ID), rh.Node.ID)
// 		return
// 	}

// 	//////////////////////////////////////////

// 	// Open a connection to the recipient to retrieve its DH parameters
// 	destConn, err := net.Dial("tcp", txOneCoin.TargetAddress)
// 	if err != nil {
// 		fmt.Printf("%s[Node %d] [Validator] Error dialing destination %s: %v\033[0m\n", getNodeColor(rh.Node.ID), rh.Node.ID, txOneCoin.TargetAddress, err)
// 		return
// 	}
// 	defer destConn.Close()

// 	// Send a DH request
// 	reqPayload := zn.DHRequestPayload{SenderID: txOneCoin.ID}
// 	reqMsg := zn.PackMessage("dh_request", reqPayload)
// 	if err := zn.SendMessage(destConn, reqMsg); err != nil {
// 		fmt.Printf("%s[Node %d] [Validator] Error sending DH request: %v\033[0m\n", getNodeColor(rh.Node.ID), rh.Node.ID, err)
// 		return
// 	}

// 	// Wait for the DH response
// 	var respMsg zn.Message
// 	if err := zn.ReceiveMessage(destConn, &respMsg); err != nil {
// 		fmt.Printf("%s[Node %d] [Validator] Error receiving DH response: %v\033[0m\n", getNodeColor(rh.Node.ID), rh.Node.ID, err)
// 		return
// 	}
// 	respPayload, ok := respMsg.Payload.(zn.DHResponsePayload)
// 	if !ok {
// 		fmt.Println("DH response not conforming")
// 		return
// 	}

// 	// Validate the transaction using the parameters retrieved from the recipient
// 	//valid_0 := zg.ValidateTxDefaultCoin(txOneCoin.TxResult, txOneCoin.Old, txOneCoin.NewVal, rh.Node.G, respPayload.DestPartnerPublic, respPayload.DestEphemeralPublic, globalVKOneCoin)

// 	valid_0 := zg.ValidateTxRegister(//COMPLETE HERE

// 	//Ensure spending numbers are not already in SnList
// 	valid_1 := !containsByteSlice(SnList, txOneCoin.TxResult.SnOld)

// 	if valid_0 && valid_1 {
// 		rh.Node.logger.Info().Msg(fmt.Sprintf("%s[Node %d] [Validator] Transaction (1) validated.\033[0m", getNodeColor(rh.Node.ID), rh.Node.ID))
// 		// Add the serial numbers to the list
// 		SnList = append(SnList, txOneCoin.TxResult.SnOld)
// 		// Add the transaction to the list
// 		TxListDefaultOneCoin = append(TxListDefaultOneCoin, txOneCoin.TxResult)
// 		// Add committments to the list
// 		CmList = append(CmList, txOneCoin.TxResult.CmNew)
// 	} else {
// 		rh.Node.logger.Info().Msg(fmt.Sprintf("%s[Node %d] [Validator] Transaction invalid.\033[0m", getNodeColor(rh.Node.ID), rh.Node.ID))
// 	}

// 	//Verify PI_reg proof

// 	//ICI

// 	// // Validate the transaction using the parameters retrieved from the recipient
// 	// valid_0 := zg.ValidateTxRegisterProof(txOneCoin., txOneCoin.Old, txOneCoin.NewVal, rh.Node.G, respPayload.DestPartnerPublic, respPayload.DestEphemeralPublic, globalVKOneCoin)

// 	// //Ensure spending numbers are not already in SnList
// 	// valid_1 := !containsByteSlice(SnList, txOneCoin.TxResult.SnOld)

// 	// if valid_0 && valid_1 {
// 	// 	rh.Node.logger.Info().Msg(fmt.Sprintf("%s[Node %d] [Validator] Transaction (1) validated.\033[0m", getNodeColor(rh.Node.ID), rh.Node.ID))
// 	// 	// Add the serial numbers to the list
// 	// 	SnList = append(SnList, txOneCoin.TxResult.SnOld)
// 	// 	// Add the transaction to the list
// 	// 	TxListDefaultOneCoin = append(TxListDefaultOneCoin, txOneCoin.TxResult)
// 	// 	// Add committments to the list
// 	// 	CmList = append(CmList, txOneCoin.TxResult.CmNew)
// 	// } else {
// 	// 	rh.Node.logger.Info().Msg(fmt.Sprintf("%s[Node %d] [Validator] Transaction invalid.\033[0m", getNodeColor(rh.Node.ID), rh.Node.ID))
// 	// }

// 	///////////////////////

// 	// //txPayload, ok := tx.Payload.(zn.TxDefaultOneCoinPayload)
// 	// if !ok {
// 	// 	fmt.Println("TransactionHandler: invalid payload")
// 	// 	return
// 	// }
// 	// ID := txOneCoin.ID

// 	// fmt.Println("HERE!")
// 	// ok = zg.ValidateTxDefaultCoin(txOneCoin.TxResult,
// 	// 	txOneCoin.Old,
// 	// 	txOneCoin.NewVal,
// 	// 	rh.Node.G,
// 	// 	rh.Node.DHExchanges[ID].PartnerPublic,
// 	// 	rh.Node.DHExchanges[ID].EphemeralPublic,
// 	// 	globalVKOneCoin,
// 	// )

// 	// fmt.Println("result: ", ok)

// }

// -------------------------------
// main()
// -------------------------------
var globalCCS constraint.ConstraintSystem
var globalPK groth16.ProvingKey
var globalVK groth16.VerifyingKey

var globalCCSRegister constraint.ConstraintSystem
var globalPKRegister groth16.ProvingKey
var globalVKRegister groth16.VerifyingKey

var globalCCSOneCoin constraint.ConstraintSystem
var globalPKOneCoin groth16.ProvingKey
var globalVKOneCoin groth16.VerifyingKey

var globalCCS2Coin constraint.ConstraintSystem
var globalPK2Coin groth16.ProvingKey
var globalVK2Coin groth16.VerifyingKey

var globalCCS3Coin constraint.ConstraintSystem
var globalPK3Coin groth16.ProvingKey
var globalVK3Coin groth16.VerifyingKey

var globalCCSF1 constraint.ConstraintSystem
var globalPKF1 groth16.ProvingKey
var globalVKF1 groth16.VerifyingKey

var globalCCSF2 constraint.ConstraintSystem
var globalPKF2 groth16.ProvingKey
var globalVKF2 groth16.VerifyingKey

var globalCCSF3 constraint.ConstraintSystem
var globalPKF3 groth16.ProvingKey
var globalVKF3 groth16.VerifyingKey

var CmList [][]byte
var SnList [][]byte
var TxListDefaultOneCoin []zg.TxResultDefaultOneCoin
var TxList []zg.TxResult
var TxListTemp []zn.Transaction
var CmListTemp [][]byte
var AuxList []zn.AuxList
var InfoBid []zn.InfoBid

// containsByteSlice checks if a slice of byte slices contains a specific byte slice.
func containsByteSlice(slice [][]byte, item []byte) bool {
	for _, v := range slice {
		if bytes.Equal(v, item) {
			return true
		}
	}
	return false
}

func (n *Node) Auction(validatorAddress string, TxListTemp []zn.Transaction, AuxList []zn.AuxList, nInList []zg.Note, targetIdList []int, targetAddresses []string) zn.AuctionResultN {

	conn, _ := net.Dial("tcp", validatorAddress)

	defer conn.Close()

	//Decipher Caux
	var decCinList []*zg.DecryptedValues
	for i := 0; i < len(TxListTemp); i++ {
		fmt.Println("TxListTemp[i].Id=", TxListTemp[i].Id)
		fmt.Println("n.DHExchanges[TxListTemp[i].Id]=", n.DHExchanges[TxListTemp[i].Id])
		fmt.Println("n.DHExchanges[TxListTemp[i].Id].SharedSecret=", n.DHExchanges[TxListTemp[i].Id].SharedSecret)
		decValues, err := zg.BuildDecMimc(n.DHExchanges[TxListTemp[i].Id].SharedSecret, AuxList[i].C)
		if err != nil {
			fmt.Println("Error deciphering Caux")
		}
		decCinList = append(decCinList, decValues)
	}

	//Decipher Cin
	var decValuesList []*zg.RegDecryptedValues
	for i := 0; i < len(TxListTemp); i++ {
		txRegister, ok := TxListTemp[i].Tx.(zn.TxRegister)
		if !ok {
			fmt.Println("Error asserting Tx to TxRegister")
			continue
		}
		//fmt.Println("txRegister.EncVal = ", txRegister.EncVal)
		decRegValues, err := zg.BuildDecRegMimc(n.DHExchanges[TxListTemp[i].Id].SharedSecret, txRegister.EncVal)
		if err != nil {
			fmt.Println("Error deciphering Caux")
		}
		decValuesList = append(decValuesList, decRegValues)
		// fmt.Println("decValues n=", i, ": ", decValues)
	}

	///Perform auction
	var gammaOutList []zg.Gamma

	for i := 0; i < len(InfoBid); i++ {
		gammaOutList = append(gammaOutList, zg.Gamma{Coins: InfoBid[i].Gamma.Coins, Energy: InfoBid[i].Gamma.Energy})
	}

	var inp zg.TxProverInputHighLevelDefaultNCoin
	var rhoNewList []*big.Int
	var randNewList []*big.Int

	coinCount := len(TxListTemp)

	// Allocation des slices pour les données spécifiques à chaque coin
	inp.OldNote = make([]zg.Note, coinCount)
	inp.OldSk = make([][]byte, coinCount)
	inp.NewVal = make([]zg.Gamma, coinCount)
	inp.NewPk = make([][]byte, coinCount)
	inp.R = make([][]byte, coinCount)
	inp.EncKey = make([]bls12377.G1Affine, coinCount)
	inp.G = make([]bls12377.G1Affine, coinCount)
	inp.G_b = make([]bls12377.G1Affine, coinCount)
	inp.G_r = make([]bls12377.G1Affine, coinCount)

	for i := 0; i < coinCount; i++ {
		// Ici, on suppose que pour chaque coin, les données proviennent des mêmes index (par exemple, [1])
		inp.OldNote[i] = nInList[i]
		inp.OldSk[i] = decValuesList[i].SkIn
		inp.NewVal[i] = zg.Gamma{
			Coins:  InfoBid[i].Gamma.Coins,
			Energy: InfoBid[i].Gamma.Energy,
		}
		inp.NewPk[i] = decValuesList[i].PK

		// Génération aléatoire pour chaque coin
		rhoNew := zg.RandBigInt()
		randNew := zg.RandBigInt()
		rhoNewList = append(rhoNewList, rhoNew)
		randNewList = append(randNewList, randNew)

		//////

		fmt.Println("i = ", i)
		inp.R[i] = n.DHExchanges[targetIdList[i]].Secret
		inp.EncKey[i] = n.DHExchanges[targetIdList[i]].SharedSecret
		inp.G[i] = n.G
		inp.G_b[i] = n.DHExchanges[targetIdList[i]].PartnerPublic
		inp.G_r[i] = n.DHExchanges[targetIdList[i]].EphemeralPublic
	}

	// Remplissage des paramètres globaux (communs à tous les coins) //A CHANGER!!!!

	if coinCount != 2 {
		fmt.Println("len(TxListTemp) != 2")
	}

	var globalCCSNCoin []constraint.ConstraintSystem
	var globalPKNCoin []groth16.ProvingKey

	globalCCSNCoin = append(globalCCSNCoin, globalCCS2Coin) //dummy
	globalCCSNCoin = append(globalCCSNCoin, globalCCSOneCoin)
	globalCCSNCoin = append(globalCCSNCoin, globalCCS2Coin)
	globalCCSNCoin = append(globalCCSNCoin, globalCCS3Coin)

	globalPKNCoin = append(globalPKNCoin, globalPK2Coin) //dummy
	globalPKNCoin = append(globalPKNCoin, globalPKOneCoin)
	globalPKNCoin = append(globalPKNCoin, globalPK2Coin)
	globalPKNCoin = append(globalPKNCoin, globalPK3Coin)

	tx_out := TransactionNCoin(inp, globalCCSNCoin, globalPKNCoin, conn, n.ID, targetAddresses[0], targetIdList[0], rhoNewList, randNewList)

	// Initialisation d'une instance unique pour N coins
	var inp_ zg.TxProverInputHighLevelFN

	coinCount = len(TxListTemp)

	// Allocation des slices avec la capacité nécessaire
	inp_.InCoin = make([][]byte, 0, coinCount)
	inp_.InEnergy = make([][]byte, 0, coinCount)
	inp_.InCm = make([][]byte, 0, coinCount)
	inp_.InSn = make([][]byte, 0, coinCount)
	inp_.InPk = make([][]byte, 0, coinCount)
	inp_.InSk = make([][]byte, 0, coinCount)
	inp_.InRho = make([][]byte, 0, coinCount)
	inp_.InRand = make([][]byte, 0, coinCount)

	inp_.OutCoin = make([][]byte, 0, coinCount)
	inp_.OutEnergy = make([][]byte, 0, coinCount)
	inp_.OutCm = make([][]byte, 0, coinCount)
	inp_.OutSn = make([][]byte, 0, coinCount)
	inp_.OutPk = make([][]byte, 0, coinCount)
	inp_.OutRho = make([][]byte, 0, coinCount)
	inp_.OutRand = make([][]byte, 0, coinCount)

	inp_.C = make([][5]bls12377_fp.Element, 0, coinCount)
	inp_.DecVal = make([][5][]byte, 0, coinCount)

	inp_.SkT = make([]bls12377.G1Affine, coinCount)
	inp_.R = make([][]byte, coinCount)
	inp_.G = make([]bls12377.G1Affine, coinCount)
	inp_.G_b = make([]bls12377.G1Affine, coinCount)
	inp_.G_r = make([]bls12377.G1Affine, coinCount)
	inp_.EncKey = make([]bls12377.G1Affine, coinCount)

	for i := 0; i < coinCount; i++ {
		fmt.Println("tx_out:", tx_out)

		// Calcul du InSn pour le coin i
		h := mimcNative.NewMiMC()
		h.Write(decValuesList[i].SkIn)
		h.Write(nInList[i].Rho)
		var InSn []byte
		InSn = h.Sum(InSn)

		// Récupération de la valeur d'encryption pour ce coin
		EncVal := TxListTemp[i].Tx.(zn.TxRegister).EncVal

		// Valeurs de déchiffrement
		decC := decValuesList[i].Coins.Bytes()
		decE := decValuesList[i].Energy.Bytes()
		decB := decValuesList[i].Bid.Bytes()

		// Remplissage des champs d'entrée pour le coin i
		inp_.InCoin = append(inp_.InCoin, nInList[i].Value.Coins.Bytes())
		inp_.InEnergy = append(inp_.InEnergy, nInList[i].Value.Energy.Bytes())
		inp_.InCm = append(inp_.InCm, nInList[i].Cm)
		inp_.InSn = append(inp_.InSn, InSn)
		inp_.InPk = append(inp_.InPk, nInList[i].PkOwner)
		inp_.InSk = append(inp_.InSk, decValuesList[i].SkIn)
		inp_.InRho = append(inp_.InRho, nInList[i].Rho)
		inp_.InRand = append(inp_.InRand, nInList[i].Rand)

		// Remplissage des champs de sortie pour le coin i
		inp_.OutRho = append(inp_.OutRho, rhoNewList[i].Bytes())
		inp_.OutRand = append(inp_.OutRand, randNewList[i].Bytes())
		inp_.OutCoin = append(inp_.OutCoin, gammaOutList[i].Coins.Bytes())
		inp_.OutEnergy = append(inp_.OutEnergy, gammaOutList[i].Energy.Bytes())
		inp_.OutCm = append(inp_.OutCm, tx_out.TxResult.CmNew[i])
		inp_.OutSn = append(inp_.OutSn, tx_out.TxResult.SnOld[i])
		inp_.OutPk = append(inp_.OutPk, tx_out.TxResult.PkNew[i].Bytes())

		// Remplissage du tableau C pour ce coin (5 éléments)
		var Carray [5]bls12377_fp.Element
		Carray[0] = EncVal[0]
		Carray[1] = EncVal[1]
		Carray[2] = EncVal[2]
		Carray[3] = EncVal[3]
		Carray[4] = EncVal[4]
		inp_.C = append(inp_.C, Carray)

		// Remplissage du tableau DecVal pour ce coin (5 éléments)
		var DecValArray [5][]byte
		DecValArray[0] = decValuesList[i].PK
		DecValArray[1] = decC
		DecValArray[2] = decE
		DecValArray[3] = decValuesList[i].SkIn
		DecValArray[4] = decB
		inp_.DecVal = append(inp_.DecVal, DecValArray)

		inp_.SkT[i] = n.DHExchanges[targetIdList[i]].SharedSecret
		inp_.R[i] = n.DHExchanges[targetIdList[i]].Secret
		inp_.G[i] = n.G
		inp_.G_b[i] = n.DHExchanges[targetIdList[i]].PartnerPublic
		inp_.G_r[i] = n.DHExchanges[targetIdList[i]].EphemeralPublic
		inp_.EncKey[i] = n.DHExchanges[targetIdList[i]].SharedSecret
	}

	var globalCCSFN []constraint.ConstraintSystem
	var globalPKFN []groth16.ProvingKey

	globalCCSFN = append(globalCCSFN, globalCCSF1) //dummy
	globalCCSFN = append(globalCCSFN, globalCCSF1)
	globalCCSFN = append(globalCCSFN, globalCCSF2)
	globalCCSFN = append(globalCCSFN, globalCCSF3)

	globalPKFN = append(globalPKFN, globalPKF1) //dummy
	globalPKFN = append(globalPKFN, globalPKF1)
	globalPKFN = append(globalPKFN, globalPKF2)
	globalPKFN = append(globalPKFN, globalPKF3)

	tx_FN := TransactionFN(inp_, globalCCSFN, globalPKFN, conn, n.ID, targetAddresses[0], targetIdList[0])

	txAuction := zn.AuctionResultN{
		TxOut:    tx_out,
		TxFN:     tx_FN,
		SenderID: n.ID,
		InpDOC:   inp,
		InpF:     inp_,
		RhoNew:   rhoNewList,
		RandNew:  randNewList,
		//N:        2, //////////CHANGE
	}

	//SEND TO THE LEDGER FOR VERIFICATION

	// Packager et envoyer le message
	msg := zn.PackMessage("auction", txAuction)
	if err := zn.SendMessage(conn, msg); err != nil {
		fmt.Printf("%s[Node %d] [Transaction] Error sending transaction: %v\033[0m\n", getNodeColor(n.ID), n.ID, err)
	} else {
		fmt.Printf("%s[Node %d] [Transaction] Transaction sent successfully for validation\033[0m\n", getNodeColor(n.ID), n.ID)
	}

	return txAuction

}

func DiffieHellmanInit(nodes []*Node) {
	n := len(nodes)
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			nodes[i].DiffieHellmanKeyExchange(nodes[j].Address)
			nodes[j].DiffieHellmanKeyExchange(nodes[i].Address)
		}
	}
}

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
		if i == 0 { // The first node is the validator
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
	globalCCS, globalPK, globalVK = zg.LoadOrGenerateKeys("default")
	globalCCSRegister, globalPKRegister, globalVKRegister = zg.LoadOrGenerateKeys("register")
	globalCCSOneCoin, globalPKOneCoin, globalVKOneCoin = zg.LoadOrGenerateKeys("oneCoin")
	globalCCS2Coin, globalPK2Coin, globalVK2Coin = zg.LoadOrGenerateKeys("2coin")
	globalCCS3Coin, globalPK3Coin, globalVK3Coin = zg.LoadOrGenerateKeys("3coin")
	globalCCSF1, globalPKF1, globalVKF1 = zg.LoadOrGenerateKeys("f2")
	globalCCSF2, globalPKF2, globalVKF2 = zg.LoadOrGenerateKeys("f2")
	globalCCSF3, globalPKF3, globalVKF3 = zg.LoadOrGenerateKeys("f3")

	///////////// Diffie–Hellman key exchange //////////////
	// nodes[1].DiffieHellmanKeyExchange(nodes[2].Address)
	// nodes[2].DiffieHellmanKeyExchange(nodes[3].Address)
	// nodes[3].DiffieHellmanKeyExchange(nodes[4].Address)
	// nodes[4].DiffieHellmanKeyExchange(nodes[1].Address)
	// nodes[1].DiffieHellmanKeyExchange(nodes[3].Address)

	//DiffieHellmanInit(nodes)

	n := len(nodes)
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			nodes[i].DiffieHellmanKeyExchange(nodes[j].Address)
			nodes[j].DiffieHellmanKeyExchange(nodes[i].Address)
		}
		nodes[i].DiffieHellmanKeyExchange(nodes[0].Address)
	}

	// nodes[1].DiffieHellmanKeyExchange(nodes[0].Address)
	// nodes[2].DiffieHellmanKeyExchange(nodes[0].Address)
	// nodes[3].DiffieHellmanKeyExchange(nodes[0].Address)
	// nodes[4].DiffieHellmanKeyExchange(nodes[0].Address)

	max := 4
	//time.Sleep(1 * time.Second)
	for {
		if len(nodes[1].DHExchanges) == max && len(nodes[2].DHExchanges) == max && len(nodes[3].DHExchanges) == max {
			break
		}
	}

	fmt.Println("secret_key 1 -> 2: ", nodes[1].DHExchanges[2].SharedSecret)
	fmt.Println("ephemeral_public_key 1 -> 2: ", nodes[1].DHExchanges[2].EphemeralPublic)
	fmt.Println("partner_public_key 1 -> 2: ", nodes[1].DHExchanges[2].PartnerPublic)

	fmt.Println("secret_key 2 -> 1: ", nodes[2].DHExchanges[1].SharedSecret)
	fmt.Println("ephemeral_public_key 2 -> 1: ", nodes[2].DHExchanges[1].EphemeralPublic)
	fmt.Println("partner_public_key 2 -> 1: ", nodes[2].DHExchanges[1].PartnerPublic)

	//return

	//fmt.Println()
	//nodes[1].SendTransactionDummyImproved(nodes[0].Address, nodes[2].Address, nodes[2].ID, globalCCS, globalPK, globalVK)

	//fmt.Println("CmList: ", CmList)

	/////////////////
	///////Notes of nodes[1] (nBase, nIn, nOut)
	/////////////////

	sk_base_1 := GenerateSk()
	pkBase_1 := GeneratePk(sk_base_1)
	rho_base_1 := big.NewInt(1111).Bytes()
	rand_base_1 := big.NewInt(2222).Bytes()
	value_base_1 := zg.NewGamma(13, 2)
	nBase_1 := GenerateNote(value_base_1, pkBase_1, rho_base_1, rand_base_1)

	sk_in_1 := GenerateSk()
	pkIn_1 := GeneratePk(sk_in_1)
	rho_in_1 := big.NewInt(1111).Bytes()
	rand_in_1 := big.NewInt(2222).Bytes()
	gammaIn_1 := zg.NewGamma(13, 2)
	nIn_1 := GenerateNote(gammaIn_1, pkIn_1, rho_in_1, rand_in_1)
	fmt.Println("ici:", nIn_1)

	//new1 := zg.NewGamma(12, 5)
	sk_out_1 := GenerateSk()
	pkOut_1 := GeneratePk(sk_out_1)
	bid_1 := big.NewInt(13) //bid energy

	fmt.Println("sk_in_1:", sk_in_1)
	fmt.Println("pkOut_1:", pkOut_1)

	/////////////////
	///////Notes of nodes[2] (nBase, nIn, nOut)
	/////////////////

	sk_base_2 := GenerateSk()
	pkBase_2 := GeneratePk(sk_base_2)
	rho_base_2 := big.NewInt(1111).Bytes()
	rand_base_2 := big.NewInt(2222).Bytes()
	value_base_2 := zg.NewGamma(15, 1)
	nBase_2 := GenerateNote(value_base_2, pkBase_2, rho_base_2, rand_base_2)

	sk_in_2 := GenerateSk()
	pkIn_2 := GeneratePk(sk_in_2)
	rho_in_2 := big.NewInt(1111).Bytes()
	rand_in_2 := big.NewInt(2222).Bytes()
	gammaIn_2 := zg.NewGamma(15, 1)
	nIn_2 := GenerateNote(gammaIn_2, pkIn_2, rho_in_2, rand_in_2)

	//new1 := zg.NewGamma(12, 5)
	sk_out_2 := GenerateSk()
	pkOut_2 := GeneratePk(sk_out_2)
	bid_2 := big.NewInt(15) //bid energy

	// nInList := []zg.Note{nIn_1, nIn_2}
	// targetIdList := []int{nodes[1].ID, nodes[2].ID}
	// targetAddresses := []string{nodes[1].Address, nodes[2].Address}

	/////////////////
	///////Notes of nodes[3] (nBase, nIn, nOut)
	/////////////////

	sk_base_3 := GenerateSk()
	pkBase_3 := GeneratePk(sk_base_3)
	rho_base_3 := big.NewInt(1111).Bytes()
	rand_base_3 := big.NewInt(2222).Bytes()
	value_base_3 := zg.NewGamma(15, 1)
	nBase_3 := GenerateNote(value_base_3, pkBase_3, rho_base_3, rand_base_3)

	sk_in_3 := GenerateSk()
	pkIn_3 := GeneratePk(sk_in_3)
	rho_in_3 := big.NewInt(1111).Bytes()
	rand_in_3 := big.NewInt(2222).Bytes()
	gammaIn_3 := zg.NewGamma(15, 1)
	nIn_3 := GenerateNote(gammaIn_3, pkIn_3, rho_in_3, rand_in_3)

	//new1 := zg.NewGamma(12, 5)
	sk_out_3 := GenerateSk()
	pkOut_3 := GeneratePk(sk_out_3)
	bid_3 := big.NewInt(15) //bid energy

	nInList := []zg.Note{nIn_1, nIn_2, nIn_3}
	targetIdList := []int{nodes[1].ID, nodes[2].ID, nodes[3].ID}
	targetAddresses := []string{nodes[1].Address, nodes[2].Address, nodes[3].Address}

	/////////////////
	///////Send register transactions
	/////////////////

	nodes[1].SendTransactionRegisterN(nodes[0].Address, nodes[4].Address, nodes[4].ID, globalCCSOneCoin, globalPKOneCoin, globalVKOneCoin, globalCCSRegister, globalPKRegister, globalVKRegister, nBase_1, sk_base_1 /*new1,*/, pkIn_1, gammaIn_1, pkOut_1, sk_in_1, bid_1, nIn_1, true)
	nodes[2].SendTransactionRegisterN(nodes[0].Address, nodes[4].Address, nodes[4].ID, globalCCSOneCoin, globalPKOneCoin, globalVKOneCoin, globalCCSRegister, globalPKRegister, globalVKRegister, nBase_2, sk_base_2 /*new1,*/, pkIn_2, gammaIn_2, pkOut_2, sk_in_2, bid_2, nIn_2, true)
	nodes[3].SendTransactionRegisterN(nodes[0].Address, nodes[4].Address, nodes[4].ID, globalCCSOneCoin, globalPKOneCoin, globalVKOneCoin, globalCCSRegister, globalPKRegister, globalVKRegister, nBase_3, sk_base_3 /*new1,*/, pkIn_3, gammaIn_3, pkOut_3, sk_in_3, bid_3, nIn_3, true)

	time.Sleep(6 * time.Second)

	// for {
	// 	if len(TxListTemp) >= 2 {
	// 		break
	// 	}
	// }

	nodes[4].Auction(nodes[0].Address, TxListTemp, AuxList, nInList, targetIdList, targetAddresses)

	/////////////////
	///////Auction phase
	/////////////////

	//Auction()

	//nodes[1].SendTransactionRegisterN(nodes[0].Address, nodes[2].Address, nodes[2].ID, globalCCSOneCoin, globalPKOneCoin, globalVKOneCoin, globalCCSRegister, globalPKRegister, globalVKRegister, nBase, sk_base /*new1,*/, pkIn, gammaIn, pkOut, sk_in, bid, nIn, true)

	// Print all lists
	//fmt.Println("SnList: ", SnList)
	//fmt.Println("TxList: ", TxList)
	//fmt.Println("TxListDefaultOneCoin: ", TxListDefaultOneCoin)
	//fmt.Println("CmList: ", CmList)

	mainLogger.Info().Msg("All nodes are operational. Press Ctrl+C to stop.")
	select {}
}
