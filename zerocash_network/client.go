// client.go
package zerocash_network

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/manifoldco/promptui"
	"github.com/rs/zerolog"
)

// ClientMain se connecte au serveur et affiche un menu interactif stylé avec promptui.
func ClientMain() {
	// Connexion au serveur sur localhost:9000.
	conn, err := net.Dial("tcp", "localhost:9000")
	if err != nil {
		fmt.Printf("Erreur lors de la connexion : %v\n", err)
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
			// Ici, vous pouvez réintégrer votre code de génération et d'envoi de la preuve.
			/*
				proofBytes, publicInputs := proveCommitment(logger)
				logger.Info().Msgf("Preuve générée, taille : %d octets", len(proofBytes))
				packageToSend := ProofPackageCommittment{
					Proof:        proofBytes,
					PublicInputs: publicInputs,
				}
				msg := Message{
					Type:    "proof",
					Payload: packageToSend,
				}
				if err := SendMessage(conn, msg); err != nil {
					logger.Error().Msgf("Erreur lors de l'envoi du paquet : %v", err)
				} else {
					logger.Info().Msg("Paquet envoyé avec succès.")
				}
			*/
		case "Exécuter une autre option":
			logger.Info().Msg("Option 'Exécuter une autre option' sélectionnée")
			// Ajoutez ici le code pour l'autre option souhaitée.
		case "Quitter":
			logger.Info().Msg("Déconnexion et fermeture du client.")
			return
		}
	}
}
