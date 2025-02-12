package main

// func main() {
// 	// Exemple : un flag pour définir le port du serveur
// 	port := flag.String("port", "9000", "Port d'écoute du serveur")
// 	peer := flag.String("peer", "", "Adresse d'un pair à contacter (ex: 127.0.0.1:9001)")
// 	flag.Parse()

// 	// Lancer le serveur en lui passant le port choisi
// 	go zg.ServerMain(*port)

// 	// Attendre un court instant pour s'assurer que le serveur est démarré
// 	time.Sleep(200 * time.Millisecond)

// 	// Si un pair est spécifié, lancer le client pour se connecter à ce pair
// 	if *peer != "" {
// 		zg.ClientMain(*peer)
// 	} else {
// 		// Sinon, par exemple, afficher un menu interactif ou lancer d'autres routines clients
// 		zg.ClientMain("")
// 	}

// 	select {} // Bloquer pour éviter la terminaison immédiate
// }
