package main

import (
	"math/big"
	"os"

	. "zerocash_gnark/zerocash_gnark"
	. "zerocash_gnark/zerocash_network"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Importer votre package

// -----------------------------------------------------------------------------
// (7) main()
// -----------------------------------------------------------------------------

func main() {

	//config
	zerolog.TimeFieldFormat = "15:04:05" // Format d'heure sans date
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"})

	// 1) Charger ou générer (CCS, pk, vk)
	LoadOrGenerateKeys()

	///////////

	g1, _ := new(fr.Element).SetRandom()
	G1 := *new(bls12377.G1Affine).ScalarMultiplicationBase(g1.BigInt(new(big.Int)))

	//Prover secret
	r, _ := GenerateBls12377_frElement()
	r_bytes := r.Bytes()

	//Verifier secret
	b, _ := GenerateBls12377_frElement()
	b_bytes := b.Bytes()

	//Prover side
	G_r := new(bls12377.G1Affine).ScalarMultiplication(&G1, new(big.Int).SetBytes(r_bytes[:]))

	//Send G_r to verifier
	//TODO!

	//Verifier side
	G_b := new(bls12377.G1Affine).ScalarMultiplication(&G1, new(big.Int).SetBytes(b_bytes[:]))

	//Send G_b to prover
	//TODO!

	//Prover side
	G_r_b_prover := new(bls12377.G1Affine).ScalarMultiplication(G_b, new(big.Int).SetBytes(r_bytes[:]))

	//Verifier side
	_ = new(bls12377.G1Affine).ScalarMultiplication(G_r, new(big.Int).SetBytes(b_bytes[:]))

	//assignment.C_old_1_v = new(big.Int).SetBytes(old_coins[0].V[:])

	///////////

	// 2) On crée 2 notes old
	old1 := Note{
		Value:   NewGamma(12, 5),
		PkOwner: []byte("Alice"),
		Rho:     big.NewInt(1111).Bytes(),
		Rand:    big.NewInt(2222).Bytes(),
	}
	old1.Cm = Committment(old1.Value.Coins, old1.Value.Energy, big.NewInt(1111), big.NewInt(2222))

	old2 := Note{
		Value:   NewGamma(10, 8),
		PkOwner: []byte("Bob"),
		Rho:     big.NewInt(3333).Bytes(),
		Rand:    big.NewInt(4444).Bytes(),
	}
	old2.Cm = Committment(old2.Value.Coins, old2.Value.Energy, big.NewInt(3333), big.NewInt(4444))

	skOld1 := []byte("SK_OLD_1_XX_MIMC_ONLY")
	skOld2 := []byte("SK_OLD_2_XX_MIMC_ONLY")

	// 2 new notes
	new1 := NewGamma(9, 10)
	new2 := NewGamma(13, 3)

	pkNew1 := []byte("pkNew1_XXXXXXXXXXXX")
	pkNew2 := []byte("pkNew2_XXXXXXXXXXXX")

	// 3) Construction TxProverInputHighLevel
	inp := TxProverInputHighLevel{
		OldNotes: [2]Note{old1, old2},
		OldSk:    [2][]byte{skOld1, skOld2},
		NewVals:  [2]Gamma{new1, new2},
		NewPk:    [2][]byte{pkNew1, pkNew2},
		EncKey:   *G_r_b_prover,
		R:        r_bytes[:],
		//B:        b_bytes[:],
		G:   G1,
		G_b: *G_b,
		G_r: *G_r,
	}

	// 4) Transaction => generation
	tx := Transaction(inp)

	////////////////

	// Configuration du logger
	//log.Info().Int("Transaction done", nbConstraints).Msg("Transaction done")

	////////////////

	log.Info().Int("proofLen", len(tx.Proof)).Msg("Transaction done")
	// fmt.Printf("SnOld[0] = %x\n", tx.SnOld[0])
	// fmt.Printf("SnOld[1] = %x\n", tx.SnOld[1])
	// fmt.Printf("CmNew[0] = %x\n", tx.CmNew[0])
	// fmt.Printf("CmNew[1] = %x\n", tx.CmNew[1])
	// fmt.Printf("CNew[0]  = %x\n", tx.CNew[0])
	// fmt.Printf("CNew[1]  = %x\n", tx.CNew[1])

	// 5) Validation => doit renvoyer true
	_ = ValidateTx(tx,
		[2]Note{old1, old2},
		[2]Gamma{new1, new2},
		G1,
		*G_b,
		*G_r,
	)
	//log.Info().Int("proofLen", len(tx.Proof)).Msg("Transaction done")
	//fmt.Println("Validation =>", ok)
}
