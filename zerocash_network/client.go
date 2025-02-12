// client.go
package zerocash_network

import (
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	zg "zerocash_gnark/zerocash_gnark"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/manifoldco/promptui"
	"github.com/rs/zerolog"
)

// ClientMain se connecte au serveur et affiche un menu interactif stylé avec promptui.
func ClientMain(peerAddress string) {
	// Paramètres
	var G1 bls12377.G1Affine
	var G_b bls12377.G1Affine
	var G_r bls12377.G1Affine
	var r_bytes [32]byte
	var G_r_b bls12377.G1Affine

	// Connexion au serveur à l'adresse passée en paramètre.
	conn, err := net.Dial("tcp", peerAddress)
	if err != nil {
		fmt.Printf("Erreur lors de la connexion à %s : %v\n", peerAddress, err)
		os.Exit(1)
	}
	// La connexion sera fermée à la fin de la fonction.
	defer conn.Close()

	// Configuration d'un ConsoleWriter pour un affichage agréable.
	consoleWriter := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC1123,
	}
	logger := zerolog.New(consoleWriter).With().Timestamp().Logger()

	logger.Info().Msg("Connexion établie avec le serveur !")

	// Boucle principale pour le menu interactif avec promptui.
	for {
		menuItems := []string{
			"Envoyer une preuve",
			"Exécuter une autre option",
			"Dummy transaction",
			"Diffie–Hellman key exchange",
			"Quitter",
		}

		prompt := promptui.Select{
			Label: "Sélectionnez une option",
			Items: menuItems,
		}

		_, result, err := prompt.Run()
		if err != nil {
			logger.Error().Msgf("Erreur lors de l'affichage du menu : %v", err)
			continue
		}

		switch result {
		case "Envoyer une preuve":
			logger.Info().Msg("Option 'Envoyer une preuve' sélectionnée")
			// Votre code de génération et d'envoi de preuve peut être intégré ici.
		case "Exécuter une autre option":
			logger.Info().Msg("Option 'Exécuter une autre option' sélectionnée")
			// Intégrer ici le code pour une autre option.
		case "Diffie–Hellman key exchange":
			// Exemple de génération d'une clé Diffie–Hellman.
			g1, _ := new(fr.Element).SetRandom()
			G1 = *new(bls12377.G1Affine).ScalarMultiplicationBase(g1.BigInt(new(big.Int)))

			// Encapsuler G1
			ConfigG1 := Point{
				Type:    "DH_G1",
				Payload: G1,
			}

			msg := Message{
				Type:    "DiffieHellman",
				Payload: ConfigG1,
			}

			// Envoyer G1
			if err := SendMessage(conn, msg); err != nil {
				logger.Error().Msgf("Erreur lors de l'envoi du paquet : %v", err)
			} else {
				logger.Info().Msg("Paquet envoyé avec succès.")
			}

			r, _ := zg.GenerateBls12377_frElement()
			r_bytes = r.Bytes()

			G_r = *new(bls12377.G1Affine).ScalarMultiplication(&G1, new(big.Int).SetBytes(r_bytes[:]))

			// Encapsuler G_r
			msg = Message{
				Type: "DiffieHellman",
				Payload: Point{
					Type:    "DH_G_r",
					Payload: G_r,
				},
			}

			// Envoyer G_r
			if err := SendMessage(conn, msg); err != nil {
				logger.Error().Msgf("Erreur lors de l'envoi du paquet : %v", err)
			} else {
				logger.Info().Msg("Paquet envoyé avec succès.")
			}

			// Recevoir G_b
			var response Message
			if err := ReceiveMessage(conn, &response); err != nil {
				fmt.Printf("Erreur lors de la réception de la réponse : %v\n", err)
			} else {
				logger.Info().Msgf("Réponse du serveur : %+v", response)
			}
			G_b = response.Payload.(Point).Payload

			// Calculer G_r_b
			G_r_b = *new(bls12377.G1Affine).ScalarMultiplication(&G_b, new(big.Int).SetBytes(r_bytes[:]))
			fmt.Println("G_r_b = ", G_r_b)

		case "Dummy transaction":
			zg.LoadOrGenerateKeys("default")

		case "Quitter":
			logger.Info().Msg("Déconnexion et fermeture du client.")
			return
		}
	}
}

// func main() {

// 	//config
// 	zerolog.TimeFieldFormat = "15:04:05" // Format d'heure sans date
// 	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"})

// 	// 1) Charger ou générer (CCS, pk, vk)
// 	zg.LoadOrGenerateKeys()

// 	///////////

// 	g1, _ := new(fr.Element).SetRandom()
// 	G1 := *new(bls12377.G1Affine).ScalarMultiplicationBase(g1.BigInt(new(big.Int)))

// 	//Prover secret
// 	r, _ := zg.GenerateBls12377_frElement()
// 	r_bytes := r.Bytes()

// 	//Verifier secret
// 	b, _ := zg.GenerateBls12377_frElement()
// 	b_bytes := b.Bytes()

// 	//Prover side
// 	G_r := new(bls12377.G1Affine).ScalarMultiplication(&G1, new(big.Int).SetBytes(r_bytes[:]))

// 	//encapsulate G_r
// 	DHPoint := DiffieHellmanPoint{
// 		Type:    "G_r",
// 		Payload: *G_r,
// 	}
// 	msg := Message{
// 		Type:    "DiffieHellmanPoint",
// 		Payload: DHPoint,
// 	}
// 	//Send G_r to verifier
// 	if err := SendMessage(conn, msg); err != nil {
// 		logger.Error().Msgf("Erreur lors de l'envoi du paquet : %v", err)
// 	} else {
// 		logger.Info().Msg("Paquet envoyé avec succès.")
// 	}

// 	//Verifier side
// 	G_b := new(bls12377.G1Affine).ScalarMultiplication(&G1, new(big.Int).SetBytes(b_bytes[:]))

// 	//Send G_b to prover
// 	//TODO!

// 	//Prover side
// 	G_r_b_prover := new(bls12377.G1Affine).ScalarMultiplication(G_b, new(big.Int).SetBytes(r_bytes[:]))

// 	//Verifier side
// 	_ = new(bls12377.G1Affine).ScalarMultiplication(G_r, new(big.Int).SetBytes(b_bytes[:]))

// 	//assignment.C_old_1_v = new(big.Int).SetBytes(old_coins[0].V[:])

// 	///////////

// 	// 2) On crée 2 notes old
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
// 		EncKey:   *G_r_b_prover,
// 		R:        r_bytes[:],
// 		//B:        b_bytes[:],
// 		G:   G1,
// 		G_b: *G_b,
// 		G_r: *G_r,
// 	}

// 	// 4) Transaction => generation
// 	tx := zg.Transaction(inp)

// 	////////////////

// 	// Configuration du logger
// 	//log.Info().Int("Transaction done", nbConstraints).Msg("Transaction done")

// 	////////////////

// 	log.Info().Int("proofLen", len(tx.Proof)).Msg("Transaction done")
// 	// fmt.Printf("SnOld[0] = %x\n", tx.SnOld[0])
// 	// fmt.Printf("SnOld[1] = %x\n", tx.SnOld[1])
// 	// fmt.Printf("CmNew[0] = %x\n", tx.CmNew[0])
// 	// fmt.Printf("CmNew[1] = %x\n", tx.CmNew[1])
// 	// fmt.Printf("CNew[0]  = %x\n", tx.CNew[0])
// 	// fmt.Printf("CNew[1]  = %x\n", tx.CNew[1])

// 	// 5) Validation => doit renvoyer true
// 	_ = zg.ValidateTx(tx,
// 		[2]zg.Note{old1, old2},
// 		[2]zg.Gamma{new1, new2},
// 		G1,
// 		*G_b,
// 		*G_r,
// 	)
// 	//log.Info().Int("proofLen", len(tx.Proof)).Msg("Transaction done")
// 	//fmt.Println("Validation =>", ok)
// }
