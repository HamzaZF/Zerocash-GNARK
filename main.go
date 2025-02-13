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
	//TxHandler   *TransactionHandler   // Handler dédié pour les transactions
	TxHandler        TxHandlerInterface
	DHRequestHandler *DHRequestHandler
}

type TxHandlerInterface interface {
	HandleMessage(msg zn.Message, conn net.Conn)
}

// NewNode crée et initialise un nœud avec son ID, son port et le common G.
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
		//n.logger.Info().Msgf("Message reçu : %+v", msg)
		n.logger.Info().Msgf("Message reçu")
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
	//n.logger.Info().Msgf("Réponse reçue : %+v", response)
	n.logger.Info().Msgf("Réponse reçue")
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
		PartnerPublic:   B, // stocke ici la clé B reçue (via respPayload.Value)
		Secret:          r_bytes[:],
		SharedSecret:    shared,
	}

	//n.logger.Info().Msgf("Secret partagé calculé: %+v", shared)
	n.logger.Info().Msgf("Secret partagé calculé")
	return nil
}

// func (n *Node) SendTransactionDummy(targetAddress string, targetID int, globalCCS constraint.ConstraintSystem, globalPK groth16.ProvingKey, globalVK groth16.VerifyingKey) error {

// 	conn, err := net.Dial("tcp", targetAddress)
// 	if err != nil {
// 		n.logger.Error().Err(err).Msgf("Erreur lors du dial vers %s", targetAddress)
// 		return err
// 	}
// 	defer conn.Close()

// 	old1 := zg.Note{
// 		Value:   zg.NewGamma(12, 5),
// 		PkOwner: []byte("Alice"),
// 		Rho:     big.NewInt(1111).Bytes(),
// 		Rand:    big.NewInt(2222).Bytes(),
// 	}
// 	old1.Cm = zg.Committment(old1.Value.Coins, old1.Value.Energy, big.NewInt(1111), big.NewInt(2222))

// 	old2 := zg.Note{
// 		Value:   zg.NewGamma(10, 8),
// 		PkOwner: []byte("Bob"),
// 		Rho:     big.NewInt(3333).Bytes(),
// 		Rand:    big.NewInt(4444).Bytes(),
// 	}
// 	old2.Cm = zg.Committment(old2.Value.Coins, old2.Value.Energy, big.NewInt(3333), big.NewInt(4444))

// 	skOld1 := []byte("SK_OLD_1_XX_MIMC_ONLY")
// 	skOld2 := []byte("SK_OLD_2_XX_MIMC_ONLY")

// 	// 2 new notes
// 	new1 := zg.NewGamma(9, 10)
// 	new2 := zg.NewGamma(13, 3)

// 	pkNew1 := []byte("pkNew1_XXXXXXXXXXXX")
// 	pkNew2 := []byte("pkNew2_XXXXXXXXXXXX")

// 	// 3) Construction TxProverInputHighLevel
// 	inp := zg.TxProverInputHighLevel{
// 		OldNotes: [2]zg.Note{old1, old2},
// 		OldSk:    [2][]byte{skOld1, skOld2},
// 		NewVals:  [2]zg.Gamma{new1, new2},
// 		NewPk:    [2][]byte{pkNew1, pkNew2},
// 		EncKey:   n.DHExchanges[targetID].SharedSecret,
// 		R:        n.DHExchanges[targetID].Secret,
// 		//B:        b_bytes[:],
// 		G:   n.G,
// 		G_b: n.DHExchanges[targetID].PartnerPublic,
// 		G_r: n.DHExchanges[targetID].EphemeralPublic,
// 	}

// 	/*
// 		// Envoyer "DH_G_r" contenant A.
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

// 	tx := Transaction(inp, globalCCS, globalPK, conn, n.ID)

// 	msg := zn.PackMessage("tx", tx)
// 	if err := zn.SendMessage(conn, msg); err != nil {
// 		fmt.Printf("Erreur lors de l'envoi de la transaction: %v\n", err)
// 		return nil
// 	}

// 	n.logger.Info().Msg("Transaction envoyée avec succès.")

// 	// Envoyer la transaction
// 	//msg := zn.PackMessage("tx", proof)

// 	/*
// 		// Envoyer "DH_G_r" contenant A.
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

func (n *Node) SendTransactionDummyImproved(validatorAddress string, targetAddress string, targetID int, globalCCS constraint.ConstraintSystem, globalPK groth16.ProvingKey, globalVK groth16.VerifyingKey) error {

	conn, err := net.Dial("tcp", validatorAddress)
	if err != nil {
		n.logger.Error().Err(err).Msgf("Erreur lors du dial vers %s", validatorAddress)
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

	// 3) Construction TxProverInputHighLevel
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
	*/

	tx := Transaction(inp, globalCCS, globalPK, conn, n.ID, targetAddress, targetID)

	msg := zn.PackMessage("tx", tx)
	if err := zn.SendMessage(conn, msg); err != nil {
		fmt.Printf("Erreur lors de l'envoi de la transaction: %v\n", err)
		return nil
	}

	n.logger.Info().Msg("Transaction envoyée avec succès pour validation")

	// Envoyer la transaction
	//msg := zn.PackMessage("tx", proof)

	/*
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
	*/

	//
	return nil
}

func Transaction(inp zg.TxProverInputHighLevel, globalCCS constraint.ConstraintSystem, globalPK groth16.ProvingKey, conn net.Conn, ID int, targetAddress string, targetID int) zn.Tx {
	// 1) snOld[i] = MiMC(skOld[i], RhoOld[i]) hors-circuit
	var snOld [2][]byte
	for i := 0; i < 2; i++ {
		sn := zg.CalcSerialMimc(inp.OldSk[i], inp.OldNotes[i].Rho)
		snOld[i] = sn
	}
	// 2) generer (rhoNew, randNew), cmNew, cNew
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

		//get pk_enc
		pk_enc := encVal[0].Bytes()
		pk_enc_bytes := make([]byte, len(pk_enc))
		copy(pk_enc_bytes, pk_enc[:])
		cNew[j].PkOwner = pk_enc_bytes

		//get coins_enc
		coins_enc := encVal[1].Bytes()
		coins_enc_bytes := make([]byte, len(coins_enc))
		copy(coins_enc_bytes, coins_enc[:])
		cNew[j].Value.Coins = new(big.Int).SetBytes(coins_enc_bytes)

		//get energy_enc
		energy_enc := encVal[2].Bytes()
		energy_enc_bytes := make([]byte, len(energy_enc))
		copy(energy_enc_bytes, energy_enc[:])
		cNew[j].Value.Energy = new(big.Int).SetBytes(energy_enc_bytes)

		//get rho_enc
		rho_enc := encVal[3].Bytes()
		rho_enc_bytes := make([]byte, len(rho_enc))
		copy(rho_enc_bytes, rho_enc[:])
		cNew[j].Rho = rho_enc_bytes

		//get rand_enc
		rand_enc := encVal[4].Bytes()
		rand_enc_bytes := make([]byte, len(rand_enc))
		copy(rand_enc_bytes, rand_enc[:])
		cNew[j].Rand = rand_enc_bytes

		//get cm_enc
		cm_enc := encVal[5].Bytes()
		cm_enc_bytes := make([]byte, len(cm_enc))
		copy(cm_enc_bytes, cm_enc[:])
		cNew[j].Cm = cm_enc_bytes
	}

	// 3) Construire InputProver
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

		//pk

		//allocate with make
		ip.CNew[j] = make([][]byte, 6)
		ip.CNew[j][0] = cNew[j].PkOwner

		//coins
		ip.CNew[j][1] = cNew[j].Value.Coins.Bytes()

		//energy
		ip.CNew[j][2] = cNew[j].Value.Energy.Bytes()

		//rho
		ip.CNew[j][3] = cNew[j].Rho

		//rand
		ip.CNew[j][4] = cNew[j].Rand

		//cm
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

	// 4) Génération de preuve
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
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()
	remoteAddr := conn.RemoteAddr().String()
	payload, ok := msg.Payload.(zn.DHPayload)
	if !ok {
		fmt.Printf("Handler DiffieHellman (node %d): Payload non conforme depuis %s", dh.Node.ID, remoteAddr)
		return
	}

	if payload.SubType == "DH_G_r" {
		// Stocker A reçu de l'initiateur dans DHExchanges sous la clé = payload.ID.
		dh.Node.DHExchanges[payload.ID] = &zn.DHParams{
			EphemeralPublic: payload.Value,
		}
		logger.Info().Msgf("Handler DiffieHellman (node %d): Reçu DH_G_r de node %d", dh.Node.ID, payload.ID)
		//fmt.Printf("Handler DiffieHellman (node %d): Reçu DH_G_r de node %d : %+v\n", dh.Node.ID, payload.ID, payload.Value)

		// Générer le secret éphémère b et calculer B = G^b.
		b, _ := zg.GenerateBls12377_frElement()
		secret := b.Bytes() // secret du vérifieur
		B := *new(bls12377.G1Affine).ScalarMultiplication(&dh.Node.G, new(big.Int).SetBytes(secret[:]))
		// Calculer le secret partagé S = A^b.
		A := dh.Node.DHExchanges[payload.ID].EphemeralPublic
		shared := *new(bls12377.G1Affine).ScalarMultiplication(&A, new(big.Int).SetBytes(secret[:]))
		// Stocker ces valeurs dans DHExchanges pour ce pair.
		dh.Node.DHExchanges[payload.ID] = &zn.DHParams{
			EphemeralPublic: payload.Value, // A reçu de l'initiateur
			PartnerPublic:   B,             // B calculé par le vérifieur
			Secret:          secret[:],
			SharedSecret:    shared,
		}

		//fmt.Printf("Handler DiffieHellman (node %d): Secret partagé calculé: %+v\n", dh.Node.ID, shared)
		logger.Info().Msgf("Handler DiffieHellman (node %d): Secret partagé calculé", dh.Node.ID)

		// Envoyer le message "DH_G_b" contenant B.
		respPayload := zn.DHPayload{
			ID:      dh.Node.ID,
			SubType: "DH_G_b",
			Value:   B,
		}
		respMsg := zn.PackMessage("DiffieHellman", respPayload)
		if err := zn.SendMessage(conn, respMsg); err != nil {
			logger.Error().Err(err).Msgf("Handler DiffieHellman (node %d): Erreur lors de l'envoi de DH_G_b vers node %d", dh.Node.ID, payload.ID)
			//fmt.Printf("Handler DiffieHellman (node %d): Erreur lors de l'envoi de DH_G_b vers node %d: %v\n", dh.Node.ID, payload.ID, err)
		} else {
			logger.Info().Msgf("Handler DiffieHellman (node %d): DH_G_b envoyé vers node %d", dh.Node.ID, payload.ID)
			//fmt.Printf("Handler DiffieHellman (node %d): DH_G_b envoyé vers node %d\n", dh.Node.ID, payload.ID)
		}
	} else {
		logger.Error().Msgf("Handler DiffieHellman (node %d): Sous-type inconnu '%s' depuis node %d", dh.Node.ID, payload.SubType, payload.ID)
		//fmt.Printf("Handler DiffieHellman (node %d): Sous-type inconnu '%s' depuis node %d\n", dh.Node.ID, payload.SubType, payload.ID)
	}
}

// -------------------------------
// Handler Transaction
// -------------------------------

// TransactionHandler gère les messages de transaction.
type TransactionHandler struct {
	Node *Node // Pointeur vers le nœud parent
}

// NewTransactionHandler retourne un nouveau TransactionHandler.
func NewTransactionHandler(node *Node) *TransactionHandler {
	return &TransactionHandler{
		Node: node,
	}
}

// HandleMessage traite le message de type "tx".
// Ici, on suppose que le payload est du type zg.TxResult (ou un type équivalent selon votre implémentation).
func (th *TransactionHandler) HandleMessage(msg zn.Message, conn net.Conn) {
	//tx, ok := msg.Payload.(zg.TxResult)
	tx, ok := msg.Payload.(zn.Tx)
	if !ok {
		fmt.Println("TransactionHandler : payload invalide")
		return
	}
	// Ici, vous pouvez traiter la transaction comme vous le souhaitez.
	fmt.Printf("Transaction reçue : %+v\n", tx)

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
// Handler Transaction Validator
// -------------------------------

type TransactionValidatorHandler struct {
	Node *Node // le validateur
}

func NewTransactionValidatorHandler(node *Node) *TransactionValidatorHandler {
	return &TransactionValidatorHandler{Node: node}
}

func (tvh *TransactionValidatorHandler) HandleMessage(msg zn.Message, conn net.Conn) {
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()
	// Extraire la transaction (supposons qu'elle soit de type zn.Tx)
	tx, ok := msg.Payload.(zn.Tx)
	if !ok {
		fmt.Println("TransactionValidatorHandler: payload invalide")
		return
	}
	// Valider la transaction
	//valid := zg.ValidateTx(tx.TxResult, tx.Old, tx.NewVal, tvh.Node.G, tvh.Node.DHExchanges[tx.ID].PartnerPublic, tvh.Node.DHExchanges[tx.ID].EphemeralPublic)

	// Ouvrir une connexion vers le destinataire pour récupérer ses paramètres DH
	destConn, err := net.Dial("tcp", tx.TargetAddress)
	if err != nil {
		fmt.Printf("Erreur lors du dial vers destination %s: %v\n", tx.TargetAddress, err)
		return
	}
	defer destConn.Close()

	// Envoyer une requête DH
	reqPayload := zn.DHRequestPayload{SenderID: tx.ID}
	reqMsg := zn.PackMessage("dh_request", reqPayload)
	if err := zn.SendMessage(destConn, reqMsg); err != nil {
		fmt.Printf("Erreur lors de l'envoi de la requête DH: %v\n", err)
		return
	}

	// Attendre la réponse DH
	var respMsg zn.Message
	if err := zn.ReceiveMessage(destConn, &respMsg); err != nil {
		fmt.Printf("Erreur lors de la réception de la réponse DH: %v\n", err)
		return
	}
	respPayload, ok := respMsg.Payload.(zn.DHResponsePayload)
	if !ok {
		fmt.Println("Réponse DH non conforme")
		return
	}

	// Valider la transaction en utilisant les paramètres récupérés du destinataire
	valid := zg.ValidateTx(tx.TxResult, tx.Old, tx.NewVal, tvh.Node.G, respPayload.DestPartnerPublic, respPayload.DestEphemeralPublic)

	if valid {
		logger.Info().Msgf("Transaction validée par le validateur (node %d).", tvh.Node.ID)
	} else {
		logger.Info().Msgf("Transaction invalide par le validateur (node %d).", tvh.Node.ID)
	}
	/*
		if valid {
			fmt.Printf("Transaction validée par le validateur (node %d).\n", tvh.Node.ID)
			// Envoyer un message de validation (si nécessaire)
			//validatedPayload := struct{ Message string }{Message: "Transaction received and intercepted"}
			validatedPayload := zn.Message{
				Type:    "tx_validated",
				Payload: "Transaction received and intercepted",
			}
			validatedMsg := zn.PackMessage("tx_validated", validatedPayload)
			// Ici, on pourrait directement répondre à l'émetteur, ou agir autrement.
			if err := zn.SendMessage(conn, validatedMsg); err != nil {
				fmt.Printf("Erreur lors de l'envoi de 'tx_validated': %v\n", err)
			}
		} else {
			fmt.Printf("Transaction invalide par le validateur (node %d).\n", tvh.Node.ID)
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
	// Exemple d'implémentation :
	// Extraire le payload de type DHRequestPayload (que vous devez définir)
	req, ok := msg.Payload.(zn.DHRequestPayload)
	if !ok {
		fmt.Println("DHRequestHandler : payload invalide")
		return
	}
	logger.Info().Msgf("DHRequestHandler (node %d) : Reçu une requête DH de l'expéditeur %d", drh.Node.ID, req.SenderID)

	// Récupérer les paramètres DH du destinataire (ici supposés stockés dans DHExchanges)
	exchange, exists := drh.Node.DHExchanges[req.SenderID]
	if !exists {
		fmt.Printf("DHRequestHandler (node %d) : Aucun échange pour l'expéditeur %d\n", drh.Node.ID, req.SenderID)
		return
	}

	// Construire la réponse avec les infos du destinataire
	resp := zn.DHResponsePayload{
		DestPartnerPublic:   exchange.PartnerPublic,
		DestEphemeralPublic: exchange.EphemeralPublic,
	}
	respMsg := zn.PackMessage("dh_response", resp)
	if err := zn.SendMessage(conn, respMsg); err != nil {
		logger.Info().Msgf("DHRequestHandler (node %d) : Erreur lors de l'envoi de la réponse DH: %v", drh.Node.ID, err)
	} else {
		logger.Info().Msgf("DHRequestHandler (node %d) : Réponse DH envoyée", drh.Node.ID)
	}
}

// -------------------------------
// main()
// -------------------------------
func main() {
	//zn.RegisterHandler("tx", NewTransactionHandler())

	mainLogger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()

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
		var node *Node
		if i == 1 { // Pour le premier nœud, on passe true
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
	// Exemple : le nœud 0 (initiateur) initie un échange avec le nœud 1 (vérifieur).
	nodes[0].DiffieHellmanKeyExchange(nodes[2].Address)
	//fmt.Println()
	nodes[0].SendTransactionDummyImproved(nodes[1].Address, nodes[2].Address, nodes[2].ID, globalCCS, globalPK, globalVK)

	mainLogger.Info().Msg("Tous les nœuds sont opérationnels. Appuyez sur Ctrl+C pour arrêter.")
	select {}
}
