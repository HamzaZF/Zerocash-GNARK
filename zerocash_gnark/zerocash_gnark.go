package zerocash_gnark

import (
	"bytes"
	"fmt"
	"math/big"
	"os"
	"time"

	mimc_bw6_761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	// Gnark + gnark-crypto
	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	mimcNative "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	// MiMC circuit
	bls12377_fp "github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	bls12377_fr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
)

// -----------------------------------------------------------------------------
// (1) Fonctions utilitaires hors-circuit
// -----------------------------------------------------------------------------

// RandBigInt renvoie un *big.Int pseudo-aléatoire (pour la démo).
func RandBigInt() *big.Int {
	return big.NewInt(time.Now().UnixNano() & 0xFFFFF)
}

func GenerateBls12377_frElement() (*bls12377_fr.Element, error) {
	var r bls12377_fr.Element
	return r.SetRandom()
}

// Committment calcule un engagement cm = MiMC(coins, energy, rho, rand).
func Committment(coins, energy, rho, r *big.Int) []byte {
	h := mimcNative.NewMiMC()
	h.Write(coins.Bytes())
	h.Write(energy.Bytes())
	h.Write(rho.Bytes())
	h.Write(r.Bytes())
	return h.Sum(nil)
}

// CalcSerialMimc : calcule sn = MiMC(sk, rho) hors-circuit, pour être cohérent
// avec la PRF en circuit.
func CalcSerialMimc(sk, rho []byte) []byte {
	h := mimcNative.NewMiMC()
	h.Write(sk)
	h.Write(rho)
	return h.Sum(nil)
}

/*
func EncZK(api frontend.API, pk, coins, energy, rho, rand, cm frontend.Variable, enc_key bls12377.G1Affine) []frontend.Variable {
	h, _ := mimc.NewMiMC(api)

	//compute H(enc_key)
	h.Write(enc_key.X.Bytes())
	h.Write(enc_key.Y.Bytes())
	h_enc_key := h.Sum()

	//compute H(H(enc_key))
	h.Write(h.Sum())
	h_h_enc_key := h.Sum()

	//compute H(H(H(enc_key)))
	h.Write(h_h_enc_key)
	h_h_h_enc_key := h.Sum()

	//compute H(H(H(H(enc_key))))
	h.Write(h_h_h_enc_key)
	h_h_h_h_enc_key := h.Sum()

	//compute H(H(H(H(H(enc_key)))))
	h.Write(h_h_h_h_enc_key)
	h_h_h_h_h_enc_key := h.Sum()

	//compute H(H(H(H(H(H(enc_key))))))
	h.Write(h_h_h_h_h_enc_key)
	h_h_h_h_h_h_enc_key := h.Sum()

	//encrypt pk
	pk_enc := api.Add(pk, h_enc_key)

	//encrypt coins
	coins_enc := api.Add(coins, h_h_enc_key)

	//encrypt energy
	energy_enc := api.Add(energy, h_h_h_enc_key)

	//encrypt rho
	rho_enc := api.Add(rho, h_h_h_h_enc_key)

	//encrypt rand
	rand_enc := api.Add(rand, h_h_h_h_h_enc_key)

	//encrypt cm
	cm_enc := api.Add(cm, h_h_h_h_h_h_enc_key)

	//return encrypted values
	return []frontend.Variable{pk_enc, coins_enc, energy_enc, rho_enc, rand_enc, cm_enc}
}
*/

func BuildEncMimc(EncKey bls12377.G1Affine, pk []byte, coins, energy, rho, rand *big.Int, cm []byte) [6]bls12377_fp.Element {

	pk_int := new(big.Int).SetBytes(pk[:])

	h := mimc_bw6_761.NewMiMC()

	EncKeyX := EncKey.X.Bytes()
	EncKeyXBytes := make([]byte, len(EncKeyX))
	copy(EncKeyXBytes[:], EncKeyX[:])

	EncKeyY := EncKey.Y.Bytes()
	EncKeyYBytes := make([]byte, len(EncKeyY))
	copy(EncKeyYBytes[:], EncKeyY[:])

	//compute H(enc_key)
	h.Write(EncKeyXBytes)
	h.Write(EncKeyYBytes)
	var h_enc_key []byte
	h_enc_key = h.Sum(h_enc_key)

	//compute H(H(enc_key))
	var h_h_enc_key []byte
	h.Write(h_enc_key)
	h_h_enc_key = h.Sum(h_h_enc_key)

	//compute H(H(H(enc_key)))
	var h_h_h_enc_key []byte
	h.Write(h_h_enc_key)
	h_h_h_enc_key = h.Sum(h_h_h_enc_key)

	//compute H(H(H(H(enc_key))))
	var h_h_h_h_enc_key []byte
	h.Write(h_h_h_enc_key)
	h_h_h_h_enc_key = h.Sum(h_h_h_h_enc_key)

	//compute H(H(H(H(H(enc_key)))))
	var h_h_h_h_h_enc_key []byte
	h.Write(h_h_h_h_enc_key)
	h_h_h_h_h_enc_key = h.Sum(h_h_h_h_h_enc_key)

	//compute H(H(H(H(H(H(enc_key))))))
	var h_h_h_h_h_h_enc_key []byte
	h.Write(h_h_h_h_h_enc_key)
	h_h_h_h_h_h_enc_key = h.Sum(h_h_h_h_h_h_enc_key)

	//encrypt pk
	pk_ := new(bls12377_fp.Element).SetBigInt(pk_int)
	pk_enc := new(bls12377_fp.Element).Add(pk_, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_enc_key[:])))

	//encrypt coins
	coins_ := new(bls12377_fp.Element).SetBigInt(coins)
	coins_enc := new(bls12377_fp.Element).Add(coins_, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_enc_key[:])))

	//encrypt energy
	energy_ := new(bls12377_fp.Element).SetBigInt(energy)
	energy_enc := new(bls12377_fp.Element).Add(energy_, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_h_enc_key[:])))

	//encrypt rho
	rho_ := new(bls12377_fp.Element).SetBigInt(rho)
	rho_enc := new(bls12377_fp.Element).Add(rho_, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_h_h_enc_key[:])))

	//encrypt rand
	rand_ := new(bls12377_fp.Element).SetBigInt(rand)
	rand_enc := new(bls12377_fp.Element).Add(rand_, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_h_h_h_enc_key[:])))

	//encrypt cm
	cm_ := new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(cm[:]))
	cm_enc := new(bls12377_fp.Element).Add(cm_, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_h_h_h_h_enc_key[:])))

	return [6]bls12377_fp.Element{*pk_enc, *coins_enc, *energy_enc, *rho_enc, *rand_enc, *cm_enc}
}

type DecryptedValues struct {
	PK     []byte   // La valeur initiale utilisée pour "pk"
	Coins  *big.Int // La valeur initiale de "coins"
	Energy *big.Int // La valeur initiale de "energy"
	Rho    *big.Int // La valeur initiale de "rho"
	Rand   *big.Int // La valeur initiale de "rand"
	Cm     []byte   // La valeur initiale de "cm"
}

func BuildDecMimc(EncKey bls12377.G1Affine, ciphertext [6]bls12377_fp.Element) (*DecryptedValues, error) {
	// On suppose que ciphertext contient 6 éléments dans l'ordre :
	// [0]: chiffrement de pk, [1]: coins, [2]: energy, [3]: rho, [4]: rand, [5]: cm

	// Pour recréer exactement les mêmes masques, on procède comme dans BuildEncMimc.
	// On commence par récupérer EncKey.X et EncKey.Y sous forme de slice.
	EncKeyXArray := EncKey.X.Bytes() // par exemple, type [48]byte
	EncKeyXSlice := EncKeyXArray[:]  // conversion en slice
	EncKeyXBytes := make([]byte, len(EncKeyXSlice))
	copy(EncKeyXBytes, EncKeyXSlice)

	EncKeyYArray := EncKey.Y.Bytes()
	EncKeyYSlice := EncKeyYArray[:]
	EncKeyYBytes := make([]byte, len(EncKeyYSlice))
	copy(EncKeyYBytes, EncKeyYSlice)

	// // Calcul de h_enc_key
	// h1 := mimc_bw6_761.NewMiMC()
	// h1.Write(EncKeyXBytes)
	// h1.Write(EncKeyYBytes)
	// h_enc_key := h1.Sum(nil)

	// // Calcul de h_h_enc_key
	// h2 := mimc_bw6_761.NewMiMC()
	// h2.Write(h_enc_key)
	// h_h_enc_key := h2.Sum(nil)

	// // Calcul de h_h_h_enc_key
	// h3 := mimc_bw6_761.NewMiMC()
	// h3.Write(h_h_enc_key)
	// h_h_h_enc_key := h3.Sum(nil)

	// // Calcul de h_h_h_h_enc_key
	// h4 := mimc_bw6_761.NewMiMC()
	// h4.Write(h_h_h_enc_key)
	// h_h_h_h_enc_key := h4.Sum(nil)

	// // Calcul de h_h_h_h_h_enc_key
	// h5 := mimc_bw6_761.NewMiMC()
	// h5.Write(h_h_h_h_enc_key)
	// h_h_h_h_h_enc_key := h5.Sum(nil)

	// // Calcul de h_h_h_h_h_h_enc_key
	// h6 := mimc_bw6_761.NewMiMC()
	// h6.Write(h_h_h_h_h_enc_key)
	// h_h_h_h_h_h_enc_key := h6.Sum(nil)

	// Calcul de h_enc_key
	h := mimc_bw6_761.NewMiMC()
	h.Write(EncKeyXBytes)
	h.Write(EncKeyYBytes)
	h_enc_key := h.Sum(nil)

	// Calcul de h_h_enc_key
	//h := mimc_bw6_761.NewMiMC()
	h.Write(h_enc_key)
	h_h_enc_key := h.Sum(nil)

	// Calcul de h_h_h_enc_key
	//h := mimc_bw6_761.NewMiMC()
	h.Write(h_h_enc_key)
	h_h_h_enc_key := h.Sum(nil)

	// Calcul de h_h_h_h_enc_key
	//h := mimc_bw6_761.NewMiMC()
	h.Write(h_h_h_enc_key)
	h_h_h_h_enc_key := h.Sum(nil)

	// Calcul de h_h_h_h_h_enc_key
	//h := mimc_bw6_761.NewMiMC()
	h.Write(h_h_h_h_enc_key)
	h_h_h_h_h_enc_key := h.Sum(nil)

	// Calcul de h_h_h_h_h_h_enc_key
	//h := mimc_bw6_761.NewMiMC()
	h.Write(h_h_h_h_h_enc_key)
	h_h_h_h_h_h_enc_key := h.Sum(nil)

	// Pour déchiffrer, on soustrait le masque à l'élément chiffré.
	// On utilise la méthode Sub des éléments du corps fini (bls12377_fp.Element).

	// Déchiffrer pk
	maskPK := new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_enc_key))
	plainPkElem := new(bls12377_fp.Element).Sub(&ciphertext[0], maskPK)
	plainPK := plainPkElem.Bytes()

	// Déchiffrer coins
	maskCoins := new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_enc_key))
	plainCoinsElem := new(bls12377_fp.Element).Sub(&ciphertext[1], maskCoins)
	plainCoinsElemBytes := plainCoinsElem.Bytes()
	plainCoins := new(big.Int).SetBytes(plainCoinsElemBytes[:])

	// Déchiffrer energy
	maskEnergy := new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_h_enc_key))
	plainEnergyElem := new(bls12377_fp.Element).Sub(&ciphertext[2], maskEnergy)
	plainEnergyElemBytes := plainEnergyElem.Bytes()
	plainEnergy := new(big.Int).SetBytes(plainEnergyElemBytes[:])

	// Déchiffrer rho
	maskRho := new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_h_h_enc_key))
	plainRhoElem := new(bls12377_fp.Element).Sub(&ciphertext[3], maskRho)
	plainRhoElemBytes := plainRhoElem.Bytes()
	plainRho := new(big.Int).SetBytes(plainRhoElemBytes[:])

	// Déchiffrer rand
	maskRand := new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_h_h_h_enc_key))
	plainRandElem := new(bls12377_fp.Element).Sub(&ciphertext[4], maskRand)
	plainRandElemBytes := plainRandElem.Bytes()
	plainRand := new(big.Int).SetBytes(plainRandElemBytes[:])

	// Déchiffrer cm
	maskCm := new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_h_h_h_h_enc_key))
	plainCmElem := new(bls12377_fp.Element).Sub(&ciphertext[5], maskCm)
	plainCm := plainCmElem.Bytes()

	return &DecryptedValues{
		PK:     plainPK[:],
		Coins:  plainCoins,
		Energy: plainEnergy,
		Rho:    plainRho,
		Rand:   plainRand,
		Cm:     plainCm[:],
	}, nil
}

// RegDecryptedValues contient les valeurs déchiffrées issues de BuildEncRegMimc.
type RegDecryptedValues struct {
	// Pour pk_out et skIn, l’encodage était réalisé en convertissant d’abord en big.Int puis en Field Element.
	// Ici, on restitue les bytes d'origine pour pk_out et skIn.
	PK     []byte   // valeur initiale de pk_out
	SkIn   []byte   // valeur initiale de skIn
	Bid    *big.Int // valeur initiale de bid
	Coins  *big.Int // valeur initiale de gammaIn.Coins
	Energy *big.Int // valeur initiale de gammaIn.Energy
}

// BuildDecRegMimc réalise l'opération inverse de BuildEncRegMimc.
// ciphertext doit être un slice de 5 éléments dans l'ordre :
// [0]: chiffrement de pk_out, [1]: chiffrement de skIn, [2]: chiffrement de bid,
// [3]: chiffrement de gammaIn.Coins, [4]: chiffrement de gammaIn.Energy.
func BuildDecRegMimc(EncKey bls12377.G1Affine, ciphertext []bls12377_fp.Element) (*RegDecryptedValues, error) {
	// On récupère EncKey.X et EncKey.Y en slices.
	EncKeyXArray := EncKey.X.Bytes() // retourne [48]byte, par exemple
	EncKeyXSlice := EncKeyXArray[:]  // conversion en []byte
	EncKeyXBytes := make([]byte, len(EncKeyXSlice))
	copy(EncKeyXBytes, EncKeyXSlice)

	EncKeyYArray := EncKey.Y.Bytes()
	EncKeyYSlice := EncKeyYArray[:]
	EncKeyYBytes := make([]byte, len(EncKeyYSlice))
	copy(EncKeyYBytes, EncKeyYSlice)

	// Calculer les masques identiques à BuildEncRegMimc.
	// 1) h_enc_key = H(EncKeyXBytes || EncKeyYBytes)
	// h1 := mimc_bw6_761.NewMiMC()
	// h1.Write(EncKeyXBytes)
	// h1.Write(EncKeyYBytes)
	// h_enc_key := h1.Sum(nil)

	// // 2) h_h_enc_key = H(h_enc_key)
	// h2 := mimc_bw6_761.NewMiMC()
	// h2.Write(h_enc_key)
	// h_h_enc_key := h2.Sum(nil)

	// // 3) h_h_h_enc_key = H(h_h_enc_key)
	// h3 := mimc_bw6_761.NewMiMC()
	// h3.Write(h_h_enc_key)
	// h_h_h_enc_key := h3.Sum(nil)

	// // 4) h_h_h_h_enc_key = H(h_h_h_enc_key)
	// h4 := mimc_bw6_761.NewMiMC()
	// h4.Write(h_h_h_enc_key)
	// h_h_h_h_enc_key := h4.Sum(nil)

	// // 5) h_h_h_h_h_enc_key = H(h_h_h_h_enc_key)
	// h5 := mimc_bw6_761.NewMiMC()
	// h5.Write(h_h_h_h_enc_key)
	// h_h_h_h_h_enc_key := h5.Sum(nil)

	h := mimc_bw6_761.NewMiMC()
	h.Write(EncKeyXBytes)
	h.Write(EncKeyYBytes)
	h_enc_key := h.Sum(nil)

	// 2) h_h_enc_key = H(h_enc_key)
	//h := mimc_bw6_761.NewMiMC()
	h.Write(h_enc_key)
	h_h_enc_key := h.Sum(nil)

	// 3) h_h_h_enc_key = H(h_h_enc_key)
	//h := mimc_bw6_761.NewMiMC()
	h.Write(h_h_enc_key)
	h_h_h_enc_key := h.Sum(nil)

	// 4) h_h_h_h_enc_key = H(h_h_h_enc_key)
	//h := mimc_bw6_761.NewMiMC()
	h.Write(h_h_h_enc_key)
	h_h_h_h_enc_key := h.Sum(nil)

	// 5) h_h_h_h_h_enc_key = H(h_h_h_h_enc_key)
	//h := mimc_bw6_761.NewMiMC()
	h.Write(h_h_h_h_enc_key)
	h_h_h_h_h_enc_key := h.Sum(nil)

	// Déchiffrer chaque composante en soustrayant le masque correspondant.
	// Pour obtenir la valeur initiale, on utilise : plaintext = ciphertext - masque.

	// Déchiffrer pk_out
	maskPK := new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_enc_key))
	plainPkElem := new(bls12377_fp.Element).Sub(&ciphertext[0], maskPK)
	plainPkElemBytes := plainPkElem.Bytes()
	plainPK := plainPkElemBytes[:] // conversion en slice

	// Déchiffrer skIn
	maskSkIn := new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_enc_key))
	plainSkInElem := new(bls12377_fp.Element).Sub(&ciphertext[1], maskSkIn)
	plainSkInElemBytes := plainSkInElem.Bytes()
	plainSkIn := plainSkInElemBytes[:]

	// Déchiffrer bid
	maskBid := new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_h_enc_key))
	plainBidElem := new(bls12377_fp.Element).Sub(&ciphertext[2], maskBid)
	plainBidElemBytes := plainBidElem.Bytes()
	plainBid := new(big.Int).SetBytes(plainBidElemBytes[:])

	// Déchiffrer gammaIn.Coins
	maskCoins := new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_h_h_enc_key))
	plainCoinsElem := new(bls12377_fp.Element).Sub(&ciphertext[3], maskCoins)
	plainCoinsElemBytes := plainCoinsElem.Bytes()
	plainCoins := new(big.Int).SetBytes(plainCoinsElemBytes[:])

	// Déchiffrer gammaIn.Energy
	maskEnergy := new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_h_h_h_enc_key))
	plainEnergyElem := new(bls12377_fp.Element).Sub(&ciphertext[4], maskEnergy)
	plainEnergyElemBytes := plainEnergyElem.Bytes()
	plainEnergy := new(big.Int).SetBytes(plainEnergyElemBytes[:])

	return &RegDecryptedValues{
		PK:     plainPK,
		SkIn:   plainSkIn,
		Bid:    plainBid,
		Coins:  plainCoins,
		Energy: plainEnergy,
	}, nil
}

type TxProverInputHighLevelDefaultNCoin struct {
	OldNote []Note              // Un tableau de Note (une par coin)
	OldSk   [][]byte            // Un tableau de clés secrètes (une par coin)
	NewVal  []Gamma             // Un tableau de Gamma (une par coin)
	NewPk   [][]byte            // Un tableau de clés publiques new (une par coin)
	EncKey  []bls12377.G1Affine // Paramètre global (si chaque coin utilise la même clé d'encryption)
	R       [][]byte            // Paramètre global
	// B      []byte      // Si nécessaire
	G   []bls12377.G1Affine // Paramètre global
	G_b []bls12377.G1Affine // Paramètre global
	G_r []bls12377.G1Affine // Paramètre global
}

type TxProverInputHighLevelDefaultOneCoin struct {
	OldNote Note
	OldSk   []byte
	NewVal  Gamma
	NewPk   []byte
	EncKey  bls12377.G1Affine
	R       []byte
	// B      []byte
	G   bls12377.G1Affine
	G_b bls12377.G1Affine
	G_r bls12377.G1Affine
}

func BuildEncRegMimc(EncKey bls12377.G1Affine, gammaIn Gamma, pk_out, skIn []byte, bid *big.Int) []bls12377_fp.Element {

	pk_int := new(big.Int).SetBytes(pk_out[:])

	h := mimc_bw6_761.NewMiMC()

	EncKeyX := EncKey.X.Bytes()
	EncKeyXBytes := make([]byte, len(EncKeyX))
	copy(EncKeyXBytes[:], EncKeyX[:])

	EncKeyY := EncKey.Y.Bytes()
	EncKeyYBytes := make([]byte, len(EncKeyY))
	copy(EncKeyYBytes[:], EncKeyY[:])

	//compute H(enc_key)
	h.Write(EncKeyXBytes)
	h.Write(EncKeyYBytes)
	var h_enc_key []byte
	h_enc_key = h.Sum(h_enc_key)

	//compute H(H(enc_key))
	var h_h_enc_key []byte
	h.Write(h_enc_key)
	h_h_enc_key = h.Sum(h_h_enc_key)

	//compute H(H(H(enc_key)))
	var h_h_h_enc_key []byte
	h.Write(h_h_enc_key)
	h_h_h_enc_key = h.Sum(h_h_h_enc_key)

	//compute H(H(H(H(enc_key))))
	var h_h_h_h_enc_key []byte
	h.Write(h_h_h_enc_key)
	h_h_h_h_enc_key = h.Sum(h_h_h_h_enc_key)

	//compute H(H(H(H(H(enc_key)))))
	var h_h_h_h_h_enc_key []byte
	h.Write(h_h_h_h_enc_key)
	h_h_h_h_h_enc_key = h.Sum(h_h_h_h_h_enc_key)

	// //compute H(H(H(H(H(H(enc_key))))))
	// var h_h_h_h_h_h_enc_key []byte
	// h.Write(h_h_h_h_h_enc_key)
	// h_h_h_h_h_h_enc_key = h.Sum(h_h_h_h_h_h_enc_key)

	//c.PkOut, c.SkIn, c.Bid, c.GammaInCoins, c.GammaInEnergy, c.EncKey)

	//encrypt pk
	pk_ := new(bls12377_fp.Element).SetBigInt(pk_int)
	pk_enc := new(bls12377_fp.Element).Add(pk_, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_enc_key[:])))

	//encrypt SkIn
	skIn_ := new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(skIn[:]))
	skIn_enc := new(bls12377_fp.Element).Add(skIn_, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_enc_key[:])))

	//encrypt bid
	bid_ := new(bls12377_fp.Element).SetBigInt(bid)
	bid_enc := new(bls12377_fp.Element).Add(bid_, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_h_enc_key[:])))

	//encrypt coins
	coins_ := new(bls12377_fp.Element).SetBigInt(gammaIn.Coins)
	coins_enc := new(bls12377_fp.Element).Add(coins_, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_h_h_enc_key[:])))

	//encrypt energy
	energy_ := new(bls12377_fp.Element).SetBigInt(gammaIn.Energy)
	energy_enc := new(bls12377_fp.Element).Add(energy_, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_h_h_h_enc_key[:])))

	////encrypt sk_in
	//skIn_ := new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(skIn[:]))
	//skIn_enc := new(bls12377_fp.Element).Add(skIn_, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_h_h_enc_key[:])))

	////encrypt bid
	//bid_ := new(bls12377_fp.Element).SetBigInt(bid)
	//bid_enc := new(bls12377_fp.Element).Add(bid_, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_h_h_h_enc_key[:])))

	return []bls12377_fp.Element{*pk_enc, *skIn_enc, *bid_enc, *coins_enc, *energy_enc}
}

// -----------------------------------------------------------------------------
// (2) Structures
// -----------------------------------------------------------------------------

// Gamma stocke (Coins, Energy)
type Gamma struct {
	Coins  *big.Int
	Energy *big.Int
}

func NewGamma(coins, energy int64) Gamma {
	return Gamma{
		Coins:  big.NewInt(coins),
		Energy: big.NewInt(energy),
	}
}

// Note = (Gamma, pkOwner, Rho, Rand, Cm)
type Note struct {
	Value   Gamma
	PkOwner []byte
	Rho     []byte
	Rand    []byte
	Cm      []byte
}

// -----------------------------------------------------------------------------
// (3) CircuitTxMulti: 2 old notes -> 2 new notes
// -----------------------------------------------------------------------------

type CircuitTxMulti struct {
	// old note data (PUBLIC)
	OldCoins  [2]frontend.Variable `gnark:",public"`
	OldEnergy [2]frontend.Variable `gnark:",public"`
	CmOld     [2]frontend.Variable `gnark:",public"`
	SnOld     [2]frontend.Variable `gnark:",public"` // PRF_{sk}(rho)
	PkOld     [2]frontend.Variable `gnark:",public"`

	// new note data (PUBLIC)
	NewCoins  [2]frontend.Variable    `gnark:",public"`
	NewEnergy [2]frontend.Variable    `gnark:",public"`
	CmNew     [2]frontend.Variable    `gnark:",public"`
	CNew      [2][6]frontend.Variable `gnark:",public"` // "cipher" simulé

	// old note data (PRIVATE)
	SkOld   [2]frontend.Variable
	RhoOld  [2]frontend.Variable
	RandOld [2]frontend.Variable

	// new note data (PRIVATE)
	PkNew   [2]frontend.Variable
	RhoNew  [2]frontend.Variable
	RandNew [2]frontend.Variable

	////

	R frontend.Variable
	//B      frontend.Variable
	G      sw_bls12377.G1Affine `gnark:",public"`
	G_b    sw_bls12377.G1Affine `gnark:",public"`
	G_r    sw_bls12377.G1Affine `gnark:",public"`
	EncKey sw_bls12377.G1Affine

	////
}

func (c *CircuitTxMulti) Define(api frontend.API) error {
	// 1) Recalcule cmOld[i]
	hasher, _ := mimc.NewMiMC(api)
	for i := 0; i < 2; i++ {
		hasher.Reset()
		hasher.Write(c.OldCoins[i])
		hasher.Write(c.OldEnergy[i])
		hasher.Write(c.RhoOld[i])
		hasher.Write(c.RandOld[i])
		cm := hasher.Sum()
		api.AssertIsEqual(c.CmOld[i], cm)
	}
	// 2) Recalcule snOld[i] = MiMC(sk, rho) (façon PRF)
	for i := 0; i < 2; i++ {
		snComputed := PRF(api, c.SkOld[i], c.RhoOld[i])
		api.AssertIsEqual(c.SnOld[i], snComputed)
	}
	// 3) Recalcule cmNew[j]
	for j := 0; j < 2; j++ {
		hasher.Reset()
		hasher.Write(c.NewCoins[j])
		hasher.Write(c.NewEnergy[j])
		hasher.Write(c.RhoNew[j])
		hasher.Write(c.RandNew[j])
		cm := hasher.Sum()
		api.AssertIsEqual(c.CmNew[j], cm)
	}
	// 4) Recalcule cNew[j] = MiMC(pk, coins, energy, rho, rand, cm)
	for j := 0; j < 2; j++ {
		encVal := EncZK(api, c.PkNew[j],
			c.NewCoins[j], c.NewEnergy[j],
			c.RhoNew[j], c.RandNew[j], c.CmNew[j], c.EncKey)
		api.AssertIsEqual(c.CNew[j][0], encVal[0])
		api.AssertIsEqual(c.CNew[j][1], encVal[1])
		api.AssertIsEqual(c.CNew[j][2], encVal[2])
		api.AssertIsEqual(c.CNew[j][3], encVal[3])
		api.AssertIsEqual(c.CNew[j][4], encVal[4])
		api.AssertIsEqual(c.CNew[j][5], encVal[5])
	}
	// 5) Vérifie conservation
	oldCoinsSum := api.Add(c.OldCoins[0], c.OldCoins[1])
	newCoinsSum := api.Add(c.NewCoins[0], c.NewCoins[1])
	api.AssertIsEqual(oldCoinsSum, newCoinsSum)

	oldEnergySum := api.Add(c.OldEnergy[0], c.OldEnergy[1])
	newEnergySum := api.Add(c.NewEnergy[0], c.NewEnergy[1])
	api.AssertIsEqual(oldEnergySum, newEnergySum)

	// EXTRA: Encryption check

	//(G^r)^b == EncKey
	G_r_b := new(sw_bls12377.G1Affine)
	G_r_b.ScalarMul(api, c.G_b, c.R)
	api.AssertIsEqual(c.EncKey.X, G_r_b.X)
	api.AssertIsEqual(c.EncKey.Y, G_r_b.Y)

	//(G^r) == G_r
	G_r := new(sw_bls12377.G1Affine)
	G_r.ScalarMul(api, c.G, c.R)
	api.AssertIsEqual(c.G_r.X, G_r.X)
	api.AssertIsEqual(c.G_r.Y, G_r.Y)

	//check a_pk = MiMC(a_sk)
	for i := 0; i < 2; i++ {
		hasher.Reset()
		hasher.Write(c.SkOld[i])
		pk := hasher.Sum()
		api.AssertIsEqual(c.PkOld[i], pk)
	}
	return nil
}

type CircuitTxDefaultOneCoin struct {
	// old note data (PUBLIC)
	OldCoin   frontend.Variable `gnark:",public"`
	OldEnergy frontend.Variable `gnark:",public"`
	CmOld     frontend.Variable `gnark:",public"`
	SnOld     frontend.Variable `gnark:",public"` // PRF_{sk}(rho)
	PkOld     frontend.Variable `gnark:",public"`

	// new note data (PUBLIC)
	NewCoin   frontend.Variable    `gnark:",public"`
	NewEnergy frontend.Variable    `gnark:",public"`
	CmNew     frontend.Variable    `gnark:",public"`
	CNew      [6]frontend.Variable `gnark:",public"` // "cipher" simulé

	// old note data (PRIVATE)
	SkOld   frontend.Variable
	RhoOld  frontend.Variable
	RandOld frontend.Variable

	// new note data (PRIVATE)
	PkNew   frontend.Variable
	RhoNew  frontend.Variable
	RandNew frontend.Variable

	////

	R frontend.Variable
	//B      frontend.Variable
	G      sw_bls12377.G1Affine `gnark:",public"`
	G_b    sw_bls12377.G1Affine `gnark:",public"`
	G_r    sw_bls12377.G1Affine `gnark:",public"`
	EncKey sw_bls12377.G1Affine

	////
}

func (c *CircuitTxDefaultOneCoin) Define(api frontend.API) error {
	// 1) Recalcule cmOld[i]
	hasher, _ := mimc.NewMiMC(api)
	hasher.Reset()
	hasher.Write(c.OldCoin)
	hasher.Write(c.OldEnergy)
	hasher.Write(c.RhoOld)
	hasher.Write(c.RandOld)
	cm := hasher.Sum()
	api.AssertIsEqual(c.CmOld, cm)
	// 2) Recalcule snOld[i] = MiMC(sk, rho) (façon PRF)
	snComputed := PRF(api, c.SkOld, c.RhoOld)
	api.AssertIsEqual(c.SnOld, snComputed)
	// 3) Recalcule cmNew[j]
	hasher.Reset()
	hasher.Write(c.NewCoin)
	hasher.Write(c.NewEnergy)
	hasher.Write(c.RhoNew)
	hasher.Write(c.RandNew)
	cm = hasher.Sum()
	api.AssertIsEqual(c.CmNew, cm)
	// 4) Recalcule cNew[j] = MiMC(pk, coins, energy, rho, rand, cm)
	encVal := EncZK(api, c.PkNew,
		c.NewCoin, c.NewEnergy,
		c.RhoNew, c.RandNew, c.CmNew, c.EncKey)
	api.AssertIsEqual(c.CNew[0], encVal[0])
	api.AssertIsEqual(c.CNew[1], encVal[1])
	api.AssertIsEqual(c.CNew[2], encVal[2])
	api.AssertIsEqual(c.CNew[3], encVal[3])
	api.AssertIsEqual(c.CNew[4], encVal[4])
	api.AssertIsEqual(c.CNew[5], encVal[5])
	// 5) Vérifie conservation
	oldCoinsSum := api.Add(c.OldCoin, c.OldCoin)
	newCoinsSum := api.Add(c.NewCoin, c.NewCoin)
	api.AssertIsEqual(oldCoinsSum, newCoinsSum)

	oldEnergySum := api.Add(c.OldEnergy, c.OldEnergy)
	newEnergySum := api.Add(c.NewEnergy, c.NewEnergy)
	api.AssertIsEqual(oldEnergySum, newEnergySum)

	// EXTRA: Encryption check

	//(G^r)^b == EncKey
	G_r_b := new(sw_bls12377.G1Affine)
	G_r_b.ScalarMul(api, c.G_b, c.R)
	api.AssertIsEqual(c.EncKey.X, G_r_b.X)
	api.AssertIsEqual(c.EncKey.Y, G_r_b.Y)

	//(G^r) == G_r
	G_r := new(sw_bls12377.G1Affine)
	G_r.ScalarMul(api, c.G, c.R)
	api.AssertIsEqual(c.G_r.X, G_r.X)
	api.AssertIsEqual(c.G_r.Y, G_r.Y)

	//check a_pk = MiMC(a_sk)
	hasher.Reset()
	hasher.Write(c.SkOld)
	pk := hasher.Sum()
	api.AssertIsEqual(c.PkOld, pk)
	return nil
}

type InputTxF1 struct {
	InCoin   frontend.Variable
	InEnergy frontend.Variable
	InCm     frontend.Variable
	InSn     frontend.Variable
	InPk     frontend.Variable
	InSk     frontend.Variable
	InRho    frontend.Variable
	InRand   frontend.Variable

	OutCoin   frontend.Variable
	OutEnergy frontend.Variable
	OutCm     frontend.Variable
	OutSn     frontend.Variable
	OutPk     frontend.Variable
	OutRho    frontend.Variable
	OutRand   frontend.Variable

	SkT bls12377.G1Affine

	SnIn  frontend.Variable
	CmOut frontend.Variable

	C      [5][]byte //*big.Int
	DecVal [5][]byte

	EncKey bls12377.G1Affine
	R      frontend.Variable
	G      bls12377.G1Affine
	G_b    bls12377.G1Affine
	G_r    bls12377.G1Affine
}

func (ip *InputTxF1) BuildWitness() (frontend.Circuit, error) {
	var c CircuitTxF1

	// (1) champs PUBLIC du circuit
	c.InCoin = ip.InCoin
	c.InEnergy = ip.InEnergy
	c.InCm = ip.InCm
	c.InSn = ip.InSn
	c.InPk = ip.InPk
	c.InSk = ip.InSk
	c.InRho = ip.InRho
	c.InRand = ip.InRand

	c.OutCoin = ip.OutCoin
	c.OutEnergy = ip.OutEnergy
	c.OutCm = ip.OutCm
	c.OutSn = ip.OutSn
	c.OutPk = ip.OutPk
	c.OutRho = ip.OutRho
	c.OutRand = ip.OutRand

	// (2) champs PRIVÉS

	c.SkT = sw_bls12377.NewG1Affine(ip.SkT)

	//c.SnIn = ip.SnIn
	//c.CmOut = ip.CmOut

	fmt.Println("VALEURS POUR CIRCUIT F1")
	for i := 0; i < 5; i++ {
		c.C[i] = ip.C[i]
		fmt.Println("Valeur[", i, "]= ", ip.C[i])
		c.DecVal[i] = ip.DecVal[i]
		//c.C[i] = ip.OutCm
	}
	fmt.Println("FIN DES VALEURS POUR CIRCUIT F1")

	c.EncKey = sw_bls12377.NewG1Affine(ip.EncKey)

	c.R = ip.R

	c.G = sw_bls12377.NewG1Affine(ip.G)
	c.G_b = sw_bls12377.NewG1Affine(ip.G_b)
	c.G_r = sw_bls12377.NewG1Affine(ip.G_r)

	// // (1) champs PUBLIC du circuit
	// c.CmIn = ip.CmIn
	// for i := 0; i < 5; i++ {
	// 	c.CAux[i] = ip.CAux[i]
	// }
	// c.GammaInCoins = ip.GammaInCoins
	// c.GammaInEnergy = ip.GammaInEnergy
	// c.Bid = ip.Bid

	// c.G = sw_bls12377.NewG1Affine(ip.G)
	// c.G_b = sw_bls12377.NewG1Affine(ip.G_b)
	// c.G_r = sw_bls12377.NewG1Affine(ip.G_r)

	// // (2) champs PRIVÉS
	// c.InCoin = ip.InCoin
	// c.InEnergy = ip.InEnergy
	// c.RhoIn = ip.RhoIn
	// c.RandIn = ip.RandIn
	// c.SkIn = ip.SkIn
	// c.PkIn = ip.PkIn
	// c.PkOut = ip.PkOut
	// c.EncKey = sw_bls12377.NewG1Affine(ip.EncKey)
	// c.R = ip.R

	return &c, nil
}

// Structure d'input pour F multi‑coin (version FN)
type InputTxFN struct {
	// Champs coin‑spécifiques (pour chaque coin)
	InCoin   []frontend.Variable
	InEnergy []frontend.Variable
	InCm     []frontend.Variable
	InSn     []frontend.Variable
	InPk     []frontend.Variable
	InSk     []frontend.Variable
	InRho    []frontend.Variable
	InRand   []frontend.Variable

	OutCoin   []frontend.Variable
	OutEnergy []frontend.Variable
	OutCm     []frontend.Variable
	OutSn     []frontend.Variable
	OutPk     []frontend.Variable
	OutRho    []frontend.Variable
	OutRand   []frontend.Variable

	// Paramètre global commun
	SkT []bls12377.G1Affine

	// Éventuellement, d'autres champs coin‑spécifiques (si nécessaire)
	// Par exemple, si vous souhaitez avoir un SnIn et CmOut par coin :
	SnIn  []frontend.Variable
	CmOut []frontend.Variable

	// Pour chaque coin, un tableau de 5 éléments (ex. issus de l'encryption)
	C      [][5][]byte
	DecVal [][5][]byte

	// Paramètres globaux (communs à tous les coins)
	EncKey []bls12377.G1Affine
	// Si R doit être coin‑spécifique, on pourra en faire une slice, sinon global :
	R   []frontend.Variable
	G   []bls12377.G1Affine
	G_b []bls12377.G1Affine
	G_r []bls12377.G1Affine
}

func (ip *InputTxFN) BuildWitness2() (frontend.Circuit, error) {
	// On vérifie que l'input contient exactement 2 coins.
	if len(ip.InCoin) != 2 {
		return nil, fmt.Errorf("InputTxFN.BuildWitness: expected exactly 2 coins, got %d", len(ip.InCoin))
	}

	var c CircuitTxF2 // CircuitTxF2 est défini avec des tableaux statiques pour 2 coins.
	// -------------------------
	// Attribution pour le coin 0
	// -------------------------
	c.InCoin0 = ip.InCoin[0]
	c.InEnergy0 = ip.InEnergy[0]
	c.InCm0 = ip.InCm[0]
	c.InSn0 = ip.InSn[0]
	c.InPk0 = ip.InPk[0]
	c.InSk0 = ip.InSk[0]
	c.InRho0 = ip.InRho[0]
	c.InRand0 = ip.InRand[0]

	c.OutCoin0 = ip.OutCoin[0]
	c.OutEnergy0 = ip.OutEnergy[0]
	c.OutCm0 = ip.OutCm[0]
	c.OutSn0 = ip.OutSn[0]
	c.OutPk0 = ip.OutPk[0]
	c.OutRho0 = ip.OutRho[0]
	c.OutRand0 = ip.OutRand[0]

	// Si les champs optionnels sont présents pour le coin 0, on les copie
	// if len(ip.SnIn) >= 2 {
	// 	c.SnIn0 = ip.SnIn[0]
	// }
	// if len(ip.CmOut) >= 2 {
	// 	c.CmOut0 = ip.CmOut[0]
	// }

	// Recopie des tableaux d'encryption pour le coin 0
	if len(ip.C) < 2 || len(ip.DecVal) < 2 {
		return nil, fmt.Errorf("InputTxFN.BuildWitness: encryption arrays for 2 coins are required")
	}

	for i := 0; i < 5; i++ {
		c.C0[i] = ip.C[0][i]
		c.DecVal0[i] = ip.DecVal[0][i]
	}

	// -------------------------
	// Attribution pour le coin 1
	// -------------------------
	c.InCoin1 = ip.InCoin[1]
	c.InEnergy1 = ip.InEnergy[1]
	c.InCm1 = ip.InCm[1]
	c.InSn1 = ip.InSn[1]
	c.InPk1 = ip.InPk[1]
	c.InSk1 = ip.InSk[1]
	c.InRho1 = ip.InRho[1]
	c.InRand1 = ip.InRand[1]

	c.OutCoin1 = ip.OutCoin[1]
	c.OutEnergy1 = ip.OutEnergy[1]
	c.OutCm1 = ip.OutCm[1]
	c.OutSn1 = ip.OutSn[1]
	c.OutPk1 = ip.OutPk[1]
	c.OutRho1 = ip.OutRho[1]
	c.OutRand1 = ip.OutRand[1]

	// if len(ip.SnIn) >= 2 {
	// 	c.SnIn1 = ip.SnIn[1]
	// }
	// if len(ip.CmOut) >= 2 {
	// 	c.CmOut1 = ip.CmOut[1]
	// }

	// Recopie des tableaux d'encryption pour le coin 1

	for i := 0; i < 5; i++ {
		c.C1[i] = ip.C[1][i]
		c.DecVal1[i] = ip.DecVal[1][i]
	}

	// -------------------------
	// Paramètres
	// -------------------------
	c.SkT0 = sw_bls12377.NewG1Affine(ip.SkT[0])
	c.SkT1 = sw_bls12377.NewG1Affine(ip.SkT[1])
	c.EncKey0 = sw_bls12377.NewG1Affine(ip.EncKey[0])
	c.EncKey1 = sw_bls12377.NewG1Affine(ip.EncKey[1])
	c.R0 = ip.R[0]
	c.R1 = ip.R[1]
	// Pour R, on suppose qu'il s'agit d'une valeur globale (on prend le premier élément s'il s'agit d'un slice)

	c.G0 = sw_bls12377.NewG1Affine(ip.G[0])
	c.G1 = sw_bls12377.NewG1Affine(ip.G[1])
	c.G_b0 = sw_bls12377.NewG1Affine(ip.G_b[0])
	c.G_b1 = sw_bls12377.NewG1Affine(ip.G_b[1])
	c.G_r0 = sw_bls12377.NewG1Affine(ip.G_r[0])
	c.G_r1 = sw_bls12377.NewG1Affine(ip.G_r[1])

	return &c, nil
}

type TxProverInputHighLevelF1 struct {
	InCoin   []byte
	InEnergy []byte
	InCm     []byte
	InSn     []byte
	InPk     []byte
	InSk     []byte
	InRho    []byte
	InRand   []byte

	OutCoin   []byte
	OutEnergy []byte
	OutCm     []byte
	OutSn     []byte
	OutPk     []byte
	OutRho    []byte
	OutRand   []byte

	SkT bls12377.G1Affine

	//SnIn  []byte
	//CmOut []byte

	C      [5]bls12377_fp.Element
	DecVal [5][]byte

	// OldNote Note
	// OldSk   []byte
	// NewVal  Gamma
	// NewPk   []byte
	EncKey bls12377.G1Affine
	R      []byte
	// B      []byte
	G   bls12377.G1Affine
	G_b bls12377.G1Affine
	G_r bls12377.G1Affine
}

type TxProverInputHighLevelFN struct {
	// Données d'entrée pour chaque coin
	InCoin   [][]byte
	InEnergy [][]byte
	InCm     [][]byte
	InSn     [][]byte
	InPk     [][]byte
	InSk     [][]byte
	InRho    [][]byte
	InRand   [][]byte

	// Données de sortie pour chaque coin
	OutCoin   [][]byte
	OutEnergy [][]byte
	OutCm     [][]byte
	OutSn     [][]byte
	OutPk     [][]byte
	OutRho    [][]byte
	OutRand   [][]byte

	// Paramètre pour la signature (global)
	SkT []bls12377.G1Affine

	// Pour chaque coin, un tableau de 5 éléments
	C [][5]bls12377_fp.Element
	// Pour chaque coin, un tableau de 5 valeurs (en bytes)
	DecVal [][5][]byte

	// Paramètres globaux d'encryption et de circuit
	EncKey []bls12377.G1Affine
	R      [][]byte
	G      []bls12377.G1Affine
	G_b    []bls12377.G1Affine
	G_r    []bls12377.G1Affine
}

type CircuitTxF1 struct {
	// In note
	InCoin   frontend.Variable //`gnark:",public"`
	InEnergy frontend.Variable //`gnark:",public"`
	InCm     frontend.Variable //`gnark:",public"`
	InSn     frontend.Variable //`gnark:",public"` // PRF_{sk}(rho)
	InPk     frontend.Variable //`gnark:",public"`
	InSk     frontend.Variable //`gnark:",public"`
	InRho    frontend.Variable //`gnark:",public"`
	InRand   frontend.Variable //`gnark:",public"`

	// Out note
	OutCoin   frontend.Variable //`gnark:",public"`
	OutEnergy frontend.Variable //`gnark:",public"`
	OutCm     frontend.Variable //`gnark:",public"`
	OutSn     frontend.Variable //`gnark:",public"` // PRF_{sk}(rho)
	OutPk     frontend.Variable //`gnark:",public"`
	OutRho    frontend.Variable //`gnark:",public"`
	OutRand   frontend.Variable //`gnark:",public"`

	//SkT
	SkT sw_bls12377.G1Affine

	//Snin
	//SnIn  frontend.Variable
	//CmOut frontend.Variable

	//Caux
	C      [5]frontend.Variable
	DecVal [5]frontend.Variable

	// // new note data (PUBLIC)
	// NewCoin   frontend.Variable    `gnark:",public"`
	// NewEnergy frontend.Variable    `gnark:",public"`
	// CmNew     frontend.Variable    `gnark:",public"`
	// CNew      [6]frontend.Variable `gnark:",public"` // "cipher" simulé

	// // old note data (PRIVATE)
	// SkOld   frontend.Variable
	// RhoOld  frontend.Variable
	// RandOld frontend.Variable

	// // new note data (PRIVATE)
	// PkNew   frontend.Variable
	// RhoNew  frontend.Variable
	// RandNew frontend.Variable

	// ////

	R frontend.Variable
	//B      frontend.Variable
	G      sw_bls12377.G1Affine `gnark:",public"`
	G_b    sw_bls12377.G1Affine `gnark:",public"`
	G_r    sw_bls12377.G1Affine `gnark:",public"`
	EncKey sw_bls12377.G1Affine

	////
}

func (c *CircuitTxF1) Define(api frontend.API) error {

	//Decipher Caux
	decVal := DecZKReg(api, c.C[:], c.SkT)

	api.AssertIsEqual(c.DecVal[0], decVal[0])
	api.AssertIsEqual(c.DecVal[1], decVal[1])
	api.AssertIsEqual(c.DecVal[2], decVal[2])
	api.AssertIsEqual(c.DecVal[3], decVal[3])
	api.AssertIsEqual(c.DecVal[4], decVal[4])

	//Ensure snIn = PRF_{sk}(rho)
	snComputed := PRF(api, c.InSk, c.InRho)
	api.AssertIsEqual(c.InSn, snComputed)

	//Ensure auction function is correct
	api.AssertIsEqual(c.InCoin, c.OutCoin)
	api.AssertIsEqual(c.InEnergy, c.OutEnergy)

	//Ensure cmOut is well computed
	hasher, _ := mimc.NewMiMC(api)
	//hasher.Reset()
	hasher.Write(c.OutCoin)
	hasher.Write(c.OutEnergy)
	hasher.Write(c.OutRho)
	hasher.Write(c.OutRand)
	cm := hasher.Sum()
	api.AssertIsEqual(c.OutCm, cm)

	//api.AssertIsEqual(c.InCm, api.Add(c.InCoin, c.InCoin))

	//

	// // 1) Recalcule cmOld[i]
	// hasher, _ := mimc.NewMiMC(api)
	// hasher.Reset()
	// hasher.Write(c.OldCoin)
	// hasher.Write(c.OldEnergy)
	// hasher.Write(c.RhoOld)
	// hasher.Write(c.RandOld)
	// cm := hasher.Sum()
	// api.AssertIsEqual(c.CmOld, cm)
	// // 2) Recalcule snOld[i] = MiMC(sk, rho) (façon PRF)
	// snComputed := PRF(api, c.SkOld, c.RhoOld)
	// api.AssertIsEqual(c.SnOld, snComputed)
	// // 3) Recalcule cmNew[j]
	// hasher.Reset()
	// hasher.Write(c.NewCoin)
	// hasher.Write(c.NewEnergy)
	// hasher.Write(c.RhoNew)
	// hasher.Write(c.RandNew)
	// cm = hasher.Sum()
	// api.AssertIsEqual(c.CmNew, cm)
	// // 4) Recalcule cNew[j] = MiMC(pk, coins, energy, rho, rand, cm)
	// encVal := EncZK(api, c.PkNew,
	// 	c.NewCoin, c.NewEnergy,
	// 	c.RhoNew, c.RandNew, c.CmNew, c.EncKey)
	// api.AssertIsEqual(c.CNew[0], encVal[0])
	// api.AssertIsEqual(c.CNew[1], encVal[1])
	// api.AssertIsEqual(c.CNew[2], encVal[2])
	// api.AssertIsEqual(c.CNew[3], encVal[3])
	// api.AssertIsEqual(c.CNew[4], encVal[4])
	// api.AssertIsEqual(c.CNew[5], encVal[5])
	// // 5) Vérifie conservation
	// oldCoinsSum := api.Add(c.OldCoin, c.OldCoin)
	// newCoinsSum := api.Add(c.NewCoin, c.NewCoin)
	// api.AssertIsEqual(oldCoinsSum, newCoinsSum)

	// oldEnergySum := api.Add(c.OldEnergy, c.OldEnergy)
	// newEnergySum := api.Add(c.NewEnergy, c.NewEnergy)
	// api.AssertIsEqual(oldEnergySum, newEnergySum)

	// // EXTRA: Encryption check

	// //(G^r)^b == EncKey
	// G_r_b := new(sw_bls12377.G1Affine)
	// G_r_b.ScalarMul(api, c.G_b, c.R)
	// api.AssertIsEqual(c.EncKey.X, G_r_b.X)
	// api.AssertIsEqual(c.EncKey.Y, G_r_b.Y)

	// //(G^r) == G_r
	// G_r := new(sw_bls12377.G1Affine)
	// G_r.ScalarMul(api, c.G, c.R)
	// api.AssertIsEqual(c.G_r.X, G_r.X)
	// api.AssertIsEqual(c.G_r.Y, G_r.Y)

	// //check a_pk = MiMC(a_sk)
	// hasher.Reset()
	// hasher.Write(c.SkOld)
	// pk := hasher.Sum()
	// api.AssertIsEqual(c.PkOld, pk)
	return nil
}

// CircuitTxF2 définit un circuit pour deux coins.
type CircuitTxF2 struct {
	// ----- Coin 0 -----
	// Données de la note d'entrée (publiques)
	InCoin0   frontend.Variable `gnark:",public"`
	InEnergy0 frontend.Variable `gnark:",public"`
	InCm0     frontend.Variable `gnark:",public"`
	InSn0     frontend.Variable `gnark:",public"` // PRF_{sk}(rho)
	InPk0     frontend.Variable `gnark:",public"`
	InSk0     frontend.Variable `gnark:",public"`
	InRho0    frontend.Variable `gnark:",public"`
	InRand0   frontend.Variable `gnark:",public"`

	// Données de la note de sortie (publiques)
	OutCoin0   frontend.Variable `gnark:",public"`
	OutEnergy0 frontend.Variable `gnark:",public"`
	OutCm0     frontend.Variable `gnark:",public"`
	OutSn0     frontend.Variable `gnark:",public"`
	OutPk0     frontend.Variable `gnark:",public"`
	OutRho0    frontend.Variable `gnark:",public"`
	OutRand0   frontend.Variable `gnark:",public"`

	// Tableaux auxiliaires pour le coin 0 (issus de l'encryption)
	C0      [5]frontend.Variable
	DecVal0 [5]frontend.Variable

	// ----- Coin 1 -----
	// Données de la note d'entrée (publiques)
	InCoin1   frontend.Variable `gnark:",public"`
	InEnergy1 frontend.Variable `gnark:",public"`
	InCm1     frontend.Variable `gnark:",public"`
	InSn1     frontend.Variable `gnark:",public"` // PRF_{sk}(rho)
	InPk1     frontend.Variable `gnark:",public"`
	InSk1     frontend.Variable `gnark:",public"`
	InRho1    frontend.Variable `gnark:",public"`
	InRand1   frontend.Variable `gnark:",public"`

	// Données de la note de sortie (publiques)
	OutCoin1   frontend.Variable `gnark:",public"`
	OutEnergy1 frontend.Variable `gnark:",public"`
	OutCm1     frontend.Variable `gnark:",public"`
	OutSn1     frontend.Variable `gnark:",public"`
	OutPk1     frontend.Variable `gnark:",public"`
	OutRho1    frontend.Variable `gnark:",public"`
	OutRand1   frontend.Variable `gnark:",public"`

	// Tableaux auxiliaires pour le coin 1
	C1      [5]frontend.Variable
	DecVal1 [5]frontend.Variable

	// ----- Paramètres -----
	SkT0    sw_bls12377.G1Affine
	R0      frontend.Variable
	G0      sw_bls12377.G1Affine `gnark:",public"`
	G_b0    sw_bls12377.G1Affine `gnark:",public"`
	G_r0    sw_bls12377.G1Affine `gnark:",public"`
	EncKey0 sw_bls12377.G1Affine

	SkT1    sw_bls12377.G1Affine
	R1      frontend.Variable
	G1      sw_bls12377.G1Affine `gnark:",public"`
	G_b1    sw_bls12377.G1Affine `gnark:",public"`
	G_r1    sw_bls12377.G1Affine `gnark:",public"`
	EncKey1 sw_bls12377.G1Affine
}

func (c *CircuitTxF2) Define(api frontend.API) error {
	// // --- Traitement du coin 0 ---
	decVal0 := DecZKReg(api, c.C0[:], c.SkT0)
	api.AssertIsEqual(c.DecVal0[0], decVal0[0])
	api.AssertIsEqual(c.DecVal0[1], decVal0[1])
	api.AssertIsEqual(c.DecVal0[2], decVal0[2])
	api.AssertIsEqual(c.DecVal0[3], decVal0[3])
	api.AssertIsEqual(c.DecVal0[4], decVal0[4])

	// Vérification que InSn0 correspond à PRF(InSk0, InRho0)
	snComputed0 := PRF(api, c.InSk0, c.InRho0)
	api.AssertIsEqual(c.InSn0, snComputed0)

	// Vérification de la cohérence de la note pour le coin 0
	api.AssertIsEqual(c.InCoin0, c.OutCoin0)
	api.AssertIsEqual(c.InEnergy0, c.OutEnergy0)

	// Calcul de OutCm0
	hasher0, _ := mimc.NewMiMC(api)
	hasher0.Write(c.OutCoin0)
	hasher0.Write(c.OutEnergy0)
	hasher0.Write(c.OutRho0)
	hasher0.Write(c.OutRand0)
	cm0 := hasher0.Sum()
	api.AssertIsEqual(c.OutCm0, cm0)

	// // --- Traitement du coin 1 ---
	decVal1 := DecZKReg(api, c.C1[:], c.SkT1)
	api.AssertIsEqual(c.DecVal1[0], decVal1[0])
	api.AssertIsEqual(c.DecVal1[1], decVal1[1])
	api.AssertIsEqual(c.DecVal1[2], decVal1[2])
	api.AssertIsEqual(c.DecVal1[3], decVal1[3])
	api.AssertIsEqual(c.DecVal1[4], decVal1[4])

	// Vérification que InSn1 correspond à PRF(InSk1, InRho1)
	snComputed1 := PRF(api, c.InSk1, c.InRho1)
	api.AssertIsEqual(c.InSn1, snComputed1)

	// Vérification de la cohérence de la note pour le coin 1
	api.AssertIsEqual(c.InCoin1, c.OutCoin1)
	api.AssertIsEqual(c.InEnergy1, c.OutEnergy1)

	// Calcul de OutCm1
	hasher1, _ := mimc.NewMiMC(api)
	hasher1.Write(c.OutCoin1)
	hasher1.Write(c.OutEnergy1)
	hasher1.Write(c.OutRho1)
	hasher1.Write(c.OutRand1)
	cm1 := hasher1.Sum()
	api.AssertIsEqual(c.OutCm1, cm1)

	// --- Vérifications globales (pour l'encryption) ---
	// Vérifie que (G^R)^b == EncKey
	G_r_b0 := new(sw_bls12377.G1Affine)
	G_r_b0.ScalarMul(api, c.G_b0, c.R0)
	api.AssertIsEqual(c.EncKey0.X, G_r_b0.X)
	api.AssertIsEqual(c.EncKey0.Y, G_r_b0.Y)

	G_r_b1 := new(sw_bls12377.G1Affine)
	G_r_b1.ScalarMul(api, c.G_b1, c.R1)
	api.AssertIsEqual(c.EncKey1.X, G_r_b1.X)
	api.AssertIsEqual(c.EncKey1.Y, G_r_b1.Y)

	// Vérifie que (G^R) == G_r
	G_r0 := new(sw_bls12377.G1Affine)
	G_r0.ScalarMul(api, c.G0, c.R0)
	api.AssertIsEqual(c.G_r0.X, G_r0.X)
	api.AssertIsEqual(c.G_r0.Y, G_r0.Y)

	G_r1 := new(sw_bls12377.G1Affine)
	G_r1.ScalarMul(api, c.G1, c.R1)
	api.AssertIsEqual(c.G_r1.X, G_r1.X)
	api.AssertIsEqual(c.G_r1.Y, G_r1.Y)

	// Vérification de la dérivation de la clé publique pour chaque coin : InPk = MiMC(InSk)
	hasher0.Reset()
	hasher0.Write(c.InSk0)
	pk0 := hasher0.Sum()
	api.AssertIsEqual(c.InPk0, pk0)

	hasher1.Reset()
	hasher1.Write(c.InSk1)
	pk1 := hasher1.Sum()
	api.AssertIsEqual(c.InPk1, pk1)

	return nil
}

type TxProverInputHighLevelRegister struct {
	InCoin   []byte
	InEnergy []byte
	CmIn     []byte
	CAux     [5][]byte
	SkIn     []byte
	PkIn     []byte
	PkOut    []byte
	Bid      []byte
	RhoIn    []byte
	RandIn   []byte
	InVal    Gamma
	EncKey   bls12377.G1Affine
	R        []byte
	//B        []byte
	G   bls12377.G1Affine
	G_b bls12377.G1Affine
	G_r bls12377.G1Affine
}

// BuildWitness convertit TxProverInputHighLevelRegister en InputProverRegister
// puis appelle la méthode BuildWitness() déjà existante sur InputProverRegister.
func (inp *TxProverInputHighLevelRegister) BuildWitness() (frontend.Circuit, error) {
	// On crée une instance de InputProverRegister
	var ip InputProverRegister

	// Remplissage des champs PUBLICS
	// --------------------------------
	// 1) InCoin, InEnergy, CmIn sont des []byte dans inp => on les convertit en big.Int
	ip.InCoin = new(big.Int).SetBytes(inp.InCoin)
	ip.InEnergy = new(big.Int).SetBytes(inp.InEnergy)
	ip.CmIn = inp.CmIn

	// 2) CAux est un tableau [5][]byte => on convertit chaque entrée
	for i := 0; i < 5; i++ {
		ip.CAux[i] = inp.CAux[i]
	}

	// 3) GammaInCoins / GammaInEnergy / Bid => tirés de inp.InVal et inp.Bid
	ip.GammaInCoins = inp.InVal.Coins
	ip.GammaInEnergy = inp.InVal.Energy
	ip.Bid = new(big.Int).SetBytes(inp.Bid)

	// 4) Les points G, G_b, G_r, EncKey sont déjà en type bls12377.G1Affine
	// => on copie directement :
	ip.G = inp.G
	ip.G_b = inp.G_b
	ip.G_r = inp.G_r
	ip.EncKey = inp.EncKey

	// 5) R est un []byte => big.Int
	// on s'en sert pour ip.R
	ip.R = new(big.Int).SetBytes(inp.R)

	// Remplissage des champs PRIVES
	// --------------------------------
	// SkIn, PkIn, PkOut, RhoIn, RandIn => tous sont []byte dans TxProverInputHighLevelRegister.
	ip.SkIn = new(big.Int).SetBytes(inp.SkIn)
	ip.PkIn = new(big.Int).SetBytes(inp.PkIn)
	ip.PkOut = new(big.Int).SetBytes(inp.PkOut)

	ip.RhoIn = new(big.Int).SetBytes(inp.RhoIn)
	ip.RandIn = new(big.Int).SetBytes(inp.RandIn)

	// Maintenant, ip est un InputProverRegister correctement rempli.
	// On appelle ip.BuildWitness() qui renverra un CircuitTxRegister.
	return ip.BuildWitness()
}

// type CircuitTxRegister struct {
// 	// // In note data (PUBLIC)
// 	// OldCoin   frontend.Variable `gnark:",public"`
// 	// OldEnergy frontend.Variable `gnark:",public"`
// 	// CmOld     frontend.Variable `gnark:",public"`
// 	// SnOld     frontend.Variable `gnark:",public"` // PRF_{sk}(rho)
// 	// PkOld     frontend.Variable `gnark:",public"`

// 	// In note data (PUBLIC)
// 	InCoin   frontend.Variable    //`gnark:",public"`
// 	InEnergy frontend.Variable    //`gnark:",public"`
// 	CmIn     frontend.Variable    `gnark:",public"`
// 	CAux     [5]frontend.Variable `gnark:",public"` //`gnark:",public"` // "cipher" simulé

// 	SkIn  frontend.Variable
// 	PkIn  frontend.Variable
// 	PkOut frontend.Variable

// 	GammaInEnergy frontend.Variable `gnark:",public"`
// 	GammaInCoins  frontend.Variable `gnark:",public"`
// 	Bid           frontend.Variable `gnark:",public"`

// 	// new note data (PRIVATE)
// 	RhoIn  frontend.Variable
// 	RandIn frontend.Variable

// 	////

// 	R frontend.Variable
// 	//B      frontend.Variable
// 	G      sw_bls12377.G1Affine `gnark:",public"`
// 	G_b    sw_bls12377.G1Affine `gnark:",public"`
// 	G_r    sw_bls12377.G1Affine `gnark:",public"`
// 	EncKey sw_bls12377.G1Affine

// 	////
// }

// CircuitTxRegister définit un circuit pour la "registration".
type CircuitTxRegister struct {
	//
	// ====== Variables PUBLIQUES ======
	CmIn          frontend.Variable    `gnark:",public"` // engagement d'InCoin+InEnergy
	CAux          [5]frontend.Variable `gnark:",public"` // ciphertext "aux"
	GammaInEnergy frontend.Variable    `gnark:",public"` // energy "in"
	GammaInCoins  frontend.Variable    `gnark:",public"` // coin  "in"
	Bid           frontend.Variable    `gnark:",public"` // enchère
	G             sw_bls12377.G1Affine `gnark:",public"`
	G_b           sw_bls12377.G1Affine `gnark:",public"`
	G_r           sw_bls12377.G1Affine `gnark:",public"`
	//
	// ====== Variables PRIVEES ======
	InCoin   frontend.Variable    // coin "in" (secret ?)
	InEnergy frontend.Variable    // energy "in" (secret ?)
	RhoIn    frontend.Variable    // random
	RandIn   frontend.Variable    // random
	SkIn     frontend.Variable    // secret key
	PkIn     frontend.Variable    // pk derivé de SkIn => souvent secret
	PkOut    frontend.Variable    // destinataire "out"
	EncKey   sw_bls12377.G1Affine // si vous voulez la prouver en clair, ajoutez `gnark:",public"` ici
	R        frontend.Variable
}

func (c *CircuitTxRegister) Define(api frontend.API) error {
	// 1) Recalcule cmIn
	hasher, _ := mimc.NewMiMC(api)
	hasher.Reset()
	hasher.Write(c.InCoin)
	hasher.Write(c.InEnergy)
	hasher.Write(c.RhoIn)
	hasher.Write(c.RandIn)
	cm := hasher.Sum()
	api.AssertIsEqual(c.CmIn, cm)

	//check pk_in = MiMC(sk_in)
	hasher.Reset()
	hasher.Write(c.SkIn)
	pk := hasher.Sum()
	api.AssertIsEqual(c.PkIn, pk)

	// 2) Recalcule snOld[i] = MiMC(sk, rho) (façon PRF)
	//snComputed := PRF(api, c.SkIn, c.RhoIn)
	//api.AssertIsEqual(c.sn, snComputed)

	//{pk_enc, sk_enc, bid_enc, gamma_enc, energy_enc}
	// 4) Recalcule cNew[j] = MiMC(pk, coins, energy, rho, rand, cm)
	encVal := EncZKReg(api, c.PkOut, c.SkIn, c.Bid, c.GammaInCoins, c.GammaInEnergy, c.EncKey)
	//fmt.Println("encVal[0]", encVal[0])
	api.AssertIsEqual(c.CAux[0], encVal[0])
	api.AssertIsEqual(c.CAux[1], encVal[1])
	api.AssertIsEqual(c.CAux[2], encVal[2])
	api.AssertIsEqual(c.CAux[3], encVal[3])
	api.AssertIsEqual(c.CAux[4], encVal[4])

	// EXTRA: Encryption check

	//(G^r)^b == EncKey
	G_r_b := new(sw_bls12377.G1Affine)
	G_r_b.ScalarMul(api, c.G_b, c.R)
	api.AssertIsEqual(c.EncKey.X, G_r_b.X)
	api.AssertIsEqual(c.EncKey.Y, G_r_b.Y)

	//(G^r) == G_r
	G_r := new(sw_bls12377.G1Affine)
	G_r.ScalarMul(api, c.G, c.R)
	api.AssertIsEqual(c.G_r.X, G_r.X)
	api.AssertIsEqual(c.G_r.Y, G_r.Y)

	return nil

}

// PRF => MiMC(sk, rho)
func PRF(api frontend.API, sk, rho frontend.Variable) frontend.Variable {
	h, _ := mimc.NewMiMC(api)
	h.Write(sk)
	h.Write(rho)
	return h.Sum()
}

// fakeEncZK => MiMC(pk, coins, energy, rho, rand, cm)
// func fakeEncZK(api frontend.API, pk, coins, energy, rho, rand, cm frontend.Variable) frontend.Variable {
// 	h, _ := mimc.NewMiMC(api)
// 	h.Write(pk)
// 	h.Write(coins)
// 	h.Write(energy)
// 	h.Write(rho)
// 	h.Write(rand)
// 	h.Write(cm)
// 	return h.Sum()
// }

//func BuildEncMimc(pk []byte, coins, energy, rho, rand *big.Int, cm []byte) []byte {

func EncZK(api frontend.API, pk, coins, energy, rho, rand, cm frontend.Variable, enc_key sw_bls12377.G1Affine) []frontend.Variable {
	h, _ := mimc.NewMiMC(api)

	//compute H(enc_key)
	h.Write(enc_key.X)
	h.Write(enc_key.Y)
	h_enc_key := h.Sum()

	//compute H(H(enc_key))
	h.Write(h.Sum())
	h_h_enc_key := h.Sum()

	//compute H(H(H(enc_key)))
	h.Write(h_h_enc_key)
	h_h_h_enc_key := h.Sum()

	//compute H(H(H(H(enc_key))))
	h.Write(h_h_h_enc_key)
	h_h_h_h_enc_key := h.Sum()

	//compute H(H(H(H(H(enc_key)))))
	h.Write(h_h_h_h_enc_key)
	h_h_h_h_h_enc_key := h.Sum()

	//compute H(H(H(H(H(H(enc_key))))))
	h.Write(h_h_h_h_h_enc_key)
	h_h_h_h_h_h_enc_key := h.Sum()

	//encrypt pk
	pk_enc := api.Add(pk, h_enc_key)

	//encrypt coins
	coins_enc := api.Add(coins, h_h_enc_key)

	//encrypt energy
	energy_enc := api.Add(energy, h_h_h_enc_key)

	//encrypt rho
	rho_enc := api.Add(rho, h_h_h_h_enc_key)

	//encrypt rand
	rand_enc := api.Add(rand, h_h_h_h_h_enc_key)

	//encrypt cm
	cm_enc := api.Add(cm, h_h_h_h_h_h_enc_key)

	//return encrypted values
	return []frontend.Variable{pk_enc, coins_enc, energy_enc, rho_enc, rand_enc, cm_enc}
}

func EncZKReg(api frontend.API, pkOut, skIn, bid, gammaInCoins, gammaInEnergy frontend.Variable, enc_key sw_bls12377.G1Affine) []frontend.Variable {
	h, _ := mimc.NewMiMC(api)

	//compute H(enc_key)
	h.Write(enc_key.X)
	h.Write(enc_key.Y)
	h_enc_key := h.Sum()

	//compute H(H(enc_key))
	h.Write(h.Sum())
	h_h_enc_key := h.Sum()

	//compute H(H(H(enc_key)))
	h.Write(h_h_enc_key)
	h_h_h_enc_key := h.Sum()

	//compute H(H(H(H(enc_key))))
	h.Write(h_h_h_enc_key)
	h_h_h_h_enc_key := h.Sum()

	//compute H(H(H(H(H(enc_key)))))
	h.Write(h_h_h_h_enc_key)
	h_h_h_h_h_enc_key := h.Sum()

	// //compute H(H(H(H(H(H(enc_key))))))
	// h.Write(h_h_h_h_h_enc_key)
	// h_h_h_h_h_h_enc_key := h.Sum()

	//encrypt pkOut
	pk_enc := api.Add(pkOut, h_enc_key)

	//encrypt skIn
	sk_enc := api.Add(skIn, h_h_enc_key)

	//encrypt bid
	bid_enc := api.Add(bid, h_h_h_enc_key)

	//encrypt gammaIn
	gamma_enc := api.Add(gammaInCoins, h_h_h_h_enc_key)

	//encrypt energy
	energy_enc := api.Add(gammaInEnergy, h_h_h_h_h_enc_key)

	//return encrypted values
	return []frontend.Variable{pk_enc, sk_enc, bid_enc, gamma_enc, energy_enc}
}

func DecZKReg(api frontend.API, enc_values []frontend.Variable, enc_key sw_bls12377.G1Affine) []frontend.Variable {
	// On initialise le hash Mimc sur l'API donnée
	h, _ := mimc.NewMiMC(api)

	// Reproduire la même séquence de calcul que dans EncZKReg
	h.Write(enc_key.X)
	h.Write(enc_key.Y)
	h_enc_key := h.Sum()

	h.Write(h.Sum())
	h_h_enc_key := h.Sum()

	h.Write(h_h_enc_key)
	h_h_h_enc_key := h.Sum()

	h.Write(h_h_h_enc_key)
	h_h_h_h_enc_key := h.Sum()

	h.Write(h_h_h_h_enc_key)
	h_h_h_h_h_enc_key := h.Sum()

	// Puis on effectue l'opération inverse :
	// pkOut = pk_enc - h_enc_key, etc.
	pkOut := api.Sub(enc_values[0], h_enc_key)
	skIn := api.Sub(enc_values[1], h_h_enc_key)
	bid := api.Sub(enc_values[2], h_h_h_enc_key)
	gammaInCoins := api.Sub(enc_values[3], h_h_h_h_enc_key)
	gammaInEnergy := api.Sub(enc_values[4], h_h_h_h_h_enc_key)

	return []frontend.Variable{pkOut, gammaInCoins, gammaInEnergy, skIn, bid} //skIn, bid, gammaInCoins, gammaInEnergy}
}

// -----------------------------------------------------------------------------
// (4) InputProver + BuildWitness
// -----------------------------------------------------------------------------

type InputProver struct {
	// PUBLIC
	OldCoins  [2]*big.Int
	OldEnergy [2]*big.Int
	CmOld     [2][]byte
	SnOld     [2][]byte
	PkOld     [2][]byte

	NewCoins  [2]*big.Int
	NewEnergy [2]*big.Int
	CmNew     [2][]byte
	CNew      [2][][]byte

	///
	R []byte
	//B      []byte
	G      bls12377.G1Affine
	G_b    bls12377.G1Affine
	G_r    bls12377.G1Affine
	EncKey bls12377.G1Affine

	///

	// PRIVÉ
	SkOld   [2]*big.Int
	RhoOld  [2]*big.Int
	RandOld [2]*big.Int

	PkNew   [2]*big.Int
	RhoNew  [2]*big.Int
	RandNew [2]*big.Int
}

func (inp *InputProver) BuildWitness() (frontend.Circuit, error) {
	var c CircuitTxMulti
	// old
	for i := 0; i < 2; i++ {
		c.OldCoins[i] = inp.OldCoins[i]
		c.OldEnergy[i] = inp.OldEnergy[i]
		c.CmOld[i] = new(big.Int).SetBytes(inp.CmOld[i])
		c.SnOld[i] = new(big.Int).SetBytes(inp.SnOld[i])
		c.PkOld[i] = new(big.Int).SetBytes(inp.PkOld[i])

		c.SkOld[i] = inp.SkOld[i]
		c.RhoOld[i] = inp.RhoOld[i]
		c.RandOld[i] = inp.RandOld[i]
		//c.PkOld[i] = inp.PkOld[i]
	}
	// new
	for j := 0; j < 2; j++ {
		c.NewCoins[j] = inp.NewCoins[j]
		c.NewEnergy[j] = inp.NewEnergy[j]
		c.CmNew[j] = new(big.Int).SetBytes(inp.CmNew[j])

		for k := 0; k < 6; k++ {
			c.CNew[j][k] = inp.CNew[j][k]
		}

		c.PkNew[j] = inp.PkNew[j]
		c.RhoNew[j] = inp.RhoNew[j]
		c.RandNew[j] = inp.RandNew[j]
	}

	c.R = new(big.Int).SetBytes(inp.R)
	//c.B = new(big.Int).SetBytes(inp.B)
	c.G = sw_bls12377.NewG1Affine(inp.G)
	c.G_b = sw_bls12377.NewG1Affine(inp.G_b)
	c.G_r = sw_bls12377.NewG1Affine(inp.G_r)
	c.EncKey = sw_bls12377.NewG1Affine(inp.EncKey)

	return &c, nil
}

type InputProverDefaultOneCoin struct {
	// PUBLIC
	OldCoin   *big.Int
	OldEnergy *big.Int
	CmOld     []byte
	SnOld     []byte
	PkOld     []byte

	NewCoin   *big.Int
	NewEnergy *big.Int
	CmNew     []byte
	CNew      [][]byte

	///
	R []byte
	//B      []byte
	G      bls12377.G1Affine
	G_b    bls12377.G1Affine
	G_r    bls12377.G1Affine
	EncKey bls12377.G1Affine

	///

	// PRIVÉ
	SkOld   *big.Int
	RhoOld  *big.Int
	RandOld *big.Int

	PkNew   *big.Int
	RhoNew  *big.Int
	RandNew *big.Int
}

type InputProverDefaultNCoin struct {
	// PUBLIC (pour chaque coin)
	OldCoin   []*big.Int // ancien montant pour chaque coin
	OldEnergy []*big.Int // ancienne énergie pour chaque coin
	CmOld     [][]byte   // ancien commitment pour chaque coin
	SnOld     [][]byte   // ancien serial number pour chaque coin
	PkOld     [][]byte   // ancienne clé publique pour chaque coin

	NewCoin   []*big.Int // nouveau montant pour chaque coin
	NewEnergy []*big.Int // nouvelle énergie pour chaque coin
	CmNew     [][]byte   // nouveau commitment pour chaque coin
	// CNew est un slice de slice de []byte (chaque coin fournit 6 éléments comme dans TransactionOneCoin)
	CNew [][][]byte

	// PARAMÈTRES PUBLICS GLOBAUX
	R [][]byte
	//B      []byte   // si nécessaire
	G      []bls12377.G1Affine
	G_b    []bls12377.G1Affine
	G_r    []bls12377.G1Affine
	EncKey []bls12377.G1Affine

	// PRIVÉ (pour chaque coin)
	SkOld   []*big.Int // ancienne clé secrète pour chaque coin
	RhoOld  []*big.Int // ancien rho pour chaque coin
	RandOld []*big.Int // ancien rand pour chaque coin

	PkNew   []*big.Int // nouvelle clé publique pour chaque coin
	RhoNew  []*big.Int // nouveau rho pour chaque coin
	RandNew []*big.Int // nouveau rand pour chaque coin
}

func (inp *InputProverDefaultNCoin) BuildWitness2() (frontend.Circuit, error) {

	var c CircuitTxDefaultTwoCoin

	// --- Remplissage pour le coin 0 ---
	c.OldCoin0 = inp.OldCoin[0]
	c.OldEnergy0 = inp.OldEnergy[0]
	c.CmOld0 = new(big.Int).SetBytes(inp.CmOld[0])
	c.SnOld0 = new(big.Int).SetBytes(inp.SnOld[0])
	c.PkOld0 = new(big.Int).SetBytes(inp.PkOld[0])
	c.SkOld0 = inp.SkOld[0]
	c.RhoOld0 = inp.RhoOld[0]
	c.RandOld0 = inp.RandOld[0]

	c.NewCoin0 = inp.NewCoin[0]
	c.NewEnergy0 = inp.NewEnergy[0]
	c.CmNew0 = new(big.Int).SetBytes(inp.CmNew[0])
	for k := 0; k < 6; k++ {
		c.CNew0[k] = inp.CNew[0][k]
	}
	c.PkNew0 = inp.PkNew[0]
	c.RhoNew0 = inp.RhoNew[0]
	c.RandNew0 = inp.RandNew[0]

	c.R0 = new(big.Int).SetBytes(inp.R[0])
	c.G0 = sw_bls12377.NewG1Affine(inp.G[0])
	c.G_b0 = sw_bls12377.NewG1Affine(inp.G_b[0])
	c.G_r0 = sw_bls12377.NewG1Affine(inp.G_r[0])
	c.EncKey0 = sw_bls12377.NewG1Affine(inp.EncKey[0])

	// --- Remplissage pour le coin 1 ---
	c.OldCoin1 = inp.OldCoin[1]
	c.OldEnergy1 = inp.OldEnergy[1]
	c.CmOld1 = new(big.Int).SetBytes(inp.CmOld[1])
	c.SnOld1 = new(big.Int).SetBytes(inp.SnOld[1])
	c.PkOld1 = new(big.Int).SetBytes(inp.PkOld[1])
	c.SkOld1 = inp.SkOld[1]
	c.RhoOld1 = inp.RhoOld[1]
	c.RandOld1 = inp.RandOld[1]

	c.NewCoin1 = inp.NewCoin[1]
	c.NewEnergy1 = inp.NewEnergy[1]
	c.CmNew1 = new(big.Int).SetBytes(inp.CmNew[1])
	for k := 0; k < 6; k++ {
		c.CNew1[k] = inp.CNew[1][k]
	}
	c.PkNew1 = inp.PkNew[1]
	c.RhoNew1 = inp.RhoNew[1]
	c.RandNew1 = inp.RandNew[1]

	// --- Paramètres globaux (communs aux deux coins) --- ///NOOOO
	c.R1 = new(big.Int).SetBytes(inp.R[1])
	c.G1 = sw_bls12377.NewG1Affine(inp.G[1])
	c.G_b1 = sw_bls12377.NewG1Affine(inp.G_b[1])
	c.G_r1 = sw_bls12377.NewG1Affine(inp.G_r[1])
	c.EncKey1 = sw_bls12377.NewG1Affine(inp.EncKey[1])

	return &c, nil
}

type CircuitTxDefaultTwoCoin struct {
	// === Coin 0 ===
	// Données publiques de l'ancienne note
	OldCoin0   frontend.Variable `gnark:",public"`
	OldEnergy0 frontend.Variable `gnark:",public"`
	CmOld0     frontend.Variable `gnark:",public"`
	SnOld0     frontend.Variable `gnark:",public"` // PRF_{sk}(rho)
	PkOld0     frontend.Variable `gnark:",public"`

	// Données publiques de la nouvelle note
	NewCoin0   frontend.Variable    `gnark:",public"`
	NewEnergy0 frontend.Variable    `gnark:",public"`
	CmNew0     frontend.Variable    `gnark:",public"`
	CNew0      [6]frontend.Variable `gnark:",public"` // "cipher" simulé

	// Données privées de l'ancienne note
	SkOld0   frontend.Variable
	RhoOld0  frontend.Variable
	RandOld0 frontend.Variable

	// Données privées de la nouvelle note
	PkNew0   frontend.Variable
	RhoNew0  frontend.Variable
	RandNew0 frontend.Variable

	// === Coin 1 ===
	OldCoin1   frontend.Variable `gnark:",public"`
	OldEnergy1 frontend.Variable `gnark:",public"`
	CmOld1     frontend.Variable `gnark:",public"`
	SnOld1     frontend.Variable `gnark:",public"`
	PkOld1     frontend.Variable `gnark:",public"`

	NewCoin1   frontend.Variable    `gnark:",public"`
	NewEnergy1 frontend.Variable    `gnark:",public"`
	CmNew1     frontend.Variable    `gnark:",public"`
	CNew1      [6]frontend.Variable `gnark:",public"`

	SkOld1   frontend.Variable
	RhoOld1  frontend.Variable
	RandOld1 frontend.Variable

	PkNew1   frontend.Variable
	RhoNew1  frontend.Variable
	RandNew1 frontend.Variable

	// === Paramètres ===
	R0      frontend.Variable
	G0      sw_bls12377.G1Affine `gnark:",public"`
	G_b0    sw_bls12377.G1Affine `gnark:",public"`
	G_r0    sw_bls12377.G1Affine `gnark:",public"`
	EncKey0 sw_bls12377.G1Affine

	R1      frontend.Variable
	G1      sw_bls12377.G1Affine `gnark:",public"`
	G_b1    sw_bls12377.G1Affine `gnark:",public"`
	G_r1    sw_bls12377.G1Affine `gnark:",public"`
	EncKey1 sw_bls12377.G1Affine
}

func (c *CircuitTxDefaultTwoCoin) Define(api frontend.API) error {
	// ----- Pour le coin 0 -----
	// 1) Recalcule CmOld0
	hasher0, _ := mimc.NewMiMC(api)
	hasher0.Reset()
	hasher0.Write(c.OldCoin0)
	hasher0.Write(c.OldEnergy0)
	hasher0.Write(c.RhoOld0)
	hasher0.Write(c.RandOld0)
	cm0 := hasher0.Sum()
	api.AssertIsEqual(c.CmOld0, cm0)

	// 2) Recalcule SnOld0 = PRF(SkOld0, RhoOld0)
	snComputed0 := PRF(api, c.SkOld0, c.RhoOld0)
	api.AssertIsEqual(c.SnOld0, snComputed0)

	// 3) Recalcule CmNew0
	hasher0.Reset()
	hasher0.Write(c.NewCoin0)
	hasher0.Write(c.NewEnergy0)
	hasher0.Write(c.RhoNew0)
	hasher0.Write(c.RandNew0)
	cmNew0 := hasher0.Sum()
	api.AssertIsEqual(c.CmNew0, cmNew0)

	// 4) Recalcule CNew0 = EncZK(PkNew0, NewCoin0, NewEnergy0, RhoNew0, RandNew0, CmNew0, EncKey)
	encVal0 := EncZK(api, c.PkNew0, c.NewCoin0, c.NewEnergy0, c.RhoNew0, c.RandNew0, c.CmNew0, c.EncKey0)
	for i := 0; i < 6; i++ {
		api.AssertIsEqual(c.CNew0[i], encVal0[i])
	}

	// ----- Pour le coin 1 -----
	hasher1, _ := mimc.NewMiMC(api)
	hasher1.Reset()
	hasher1.Write(c.OldCoin1)
	hasher1.Write(c.OldEnergy1)
	hasher1.Write(c.RhoOld1)
	hasher1.Write(c.RandOld1)
	cm1 := hasher1.Sum()
	api.AssertIsEqual(c.CmOld1, cm1)

	snComputed1 := PRF(api, c.SkOld1, c.RhoOld1)
	api.AssertIsEqual(c.SnOld1, snComputed1)

	hasher1.Reset()
	hasher1.Write(c.NewCoin1)
	hasher1.Write(c.NewEnergy1)
	hasher1.Write(c.RhoNew1)
	hasher1.Write(c.RandNew1)
	cmNew1 := hasher1.Sum()
	api.AssertIsEqual(c.CmNew1, cmNew1)

	encVal1 := EncZK(api, c.PkNew1, c.NewCoin1, c.NewEnergy1, c.RhoNew1, c.RandNew1, c.CmNew1, c.EncKey1)
	for i := 0; i < 6; i++ {
		api.AssertIsEqual(c.CNew1[i], encVal1[i])
	}

	// ----- Conservation globale -----
	// La somme des anciens coins doit être égale à la somme des nouveaux coins
	totalOldCoin := api.Add(c.OldCoin0, c.OldCoin1)
	totalNewCoin := api.Add(c.NewCoin0, c.NewCoin1)
	api.AssertIsEqual(totalOldCoin, totalNewCoin)

	totalOldEnergy := api.Add(c.OldEnergy0, c.OldEnergy1)
	totalNewEnergy := api.Add(c.NewEnergy0, c.NewEnergy1)
	api.AssertIsEqual(totalOldEnergy, totalNewEnergy)

	// ----- Vérifications additionnelles -----
	// Vérification de l'encryption : (G^r)^b == EncKey

	G_r_b0 := new(sw_bls12377.G1Affine)
	G_r_b0.ScalarMul(api, c.G_b0, c.R0)
	api.AssertIsEqual(c.EncKey0.X, G_r_b0.X)
	api.AssertIsEqual(c.EncKey0.Y, G_r_b0.Y)

	G_r_b1 := new(sw_bls12377.G1Affine)
	G_r_b1.ScalarMul(api, c.G_b1, c.R1)
	api.AssertIsEqual(c.EncKey1.X, G_r_b1.X)
	api.AssertIsEqual(c.EncKey1.Y, G_r_b1.Y)

	// Vérification que (G^r) == G_r
	G_r0 := new(sw_bls12377.G1Affine)
	G_r0.ScalarMul(api, c.G0, c.R0)
	api.AssertIsEqual(c.G_r0.X, G_r0.X)
	api.AssertIsEqual(c.G_r0.Y, G_r0.Y)

	G_r1 := new(sw_bls12377.G1Affine)
	G_r1.ScalarMul(api, c.G1, c.R1)
	api.AssertIsEqual(c.G_r1.X, G_r1.X)
	api.AssertIsEqual(c.G_r1.Y, G_r1.Y)

	// Vérification de la dérivation de la clé publique pour chaque coin : PkOld = MiMC(SkOld)
	hasher0.Reset()
	hasher0.Write(c.SkOld0)
	pkOldComputed0 := hasher0.Sum()
	api.AssertIsEqual(c.PkOld0, pkOldComputed0)

	hasher1.Reset()
	hasher1.Write(c.SkOld1)
	pkOldComputed1 := hasher1.Sum()
	api.AssertIsEqual(c.PkOld1, pkOldComputed1)

	return nil
}

/*
tx TxResultDefaultOneCoin,
	CmIn []byte,
	CAux [5][]byte,
	GammaInEnergy *big.Int,
	GammaInCoins *big.Int,
	Bid *big.Int,
	G bls12377.G1Affine,
	G_b bls12377.G1Affine,
	G_r bls12377.G1Affine,
	vk groth16.VerifyingKey,
	PiReg []byte,
*/

type InputVerifierRegister struct {
	// // In note data (PUBLIC)
	// InCoin   frontend.Variable    //`gnark:",public"`
	// InEnergy frontend.Variable    //`gnark:",public"`
	CmIn frontend.Variable    `gnark:",public"`
	CAux [5]frontend.Variable `gnark:",public"` //`gnark:",public"` // "cipher" simulé

	// SkIn  frontend.Variable
	// PkIn  frontend.Variable
	// PkOut frontend.Variable

	GammaInEnergy frontend.Variable `gnark:",public"`
	GammaInCoins  frontend.Variable `gnark:",public"`
	Bid           frontend.Variable `gnark:",public"`

	// // new note data (PRIVATE)
	// RhoIn  frontend.Variable
	// RandIn frontend.Variable

	////

	R frontend.Variable
	//B      frontend.Variable
	G   bls12377.G1Affine `gnark:",public"`
	G_b bls12377.G1Affine `gnark:",public"`
	G_r bls12377.G1Affine `gnark:",public"`
	// EncKey bls12377.G1Affine
}

func (inp *InputVerifierRegister) BuildWitness() (frontend.Circuit, error) {
	var c CircuitTxRegister

	// c.InCoin = inp.InCoin
	// c.InEnergy = inp.InEnergy
	c.CmIn = inp.CmIn

	for k := 0; k < 5; k++ {
		c.CAux[k] = inp.CAux[k]
	}

	// c.SkIn = inp.SkIn
	// c.PkIn = inp.PkIn

	// c.PkOut = inp.PkOut

	c.GammaInCoins = inp.GammaInCoins
	c.GammaInEnergy = inp.GammaInEnergy
	c.Bid = inp.Bid

	// c.RhoIn = inp.RhoIn
	// c.RandIn = inp.RandIn

	c.R = inp.R
	//c.B = new(big.Int).SetBytes(inp.B)
	c.G = sw_bls12377.NewG1Affine(inp.G)
	c.G_b = sw_bls12377.NewG1Affine(inp.G_b)
	c.G_r = sw_bls12377.NewG1Affine(inp.G_r)
	// c.EncKey = sw_bls12377.NewG1Affine(inp.EncKey)

	return &c, nil
}

// type InputProverRegister struct {
// 	// In note data (PUBLIC)
// 	InCoin   frontend.Variable    //`gnark:",public"`
// 	InEnergy frontend.Variable    //`gnark:",public"`
// 	CmIn     frontend.Variable    `gnark:",public"`
// 	CAux     [5]frontend.Variable `gnark:",public"` //`gnark:",public"` // "cipher" simulé

// 	SkIn  frontend.Variable
// 	PkIn  frontend.Variable
// 	PkOut frontend.Variable

// 	GammaInEnergy frontend.Variable `gnark:",public"`
// 	GammaInCoins  frontend.Variable `gnark:",public"`
// 	Bid           frontend.Variable `gnark:",public"`

// 	// new note data (PRIVATE)
// 	RhoIn  frontend.Variable
// 	RandIn frontend.Variable

// 	////

// 	R frontend.Variable
// 	//B      frontend.Variable
// 	G      bls12377.G1Affine `gnark:",public"`
// 	G_b    bls12377.G1Affine `gnark:",public"`
// 	G_r    bls12377.G1Affine `gnark:",public"`
// 	EncKey bls12377.G1Affine
// }

type InputProverRegister struct {
	// ------- PUBLIC -----------
	CmIn          []byte
	CAux          [5][]byte
	GammaInCoins  *big.Int
	GammaInEnergy *big.Int
	Bid           *big.Int

	G   bls12377.G1Affine
	G_b bls12377.G1Affine
	G_r bls12377.G1Affine

	// ------- PRIVÉ -----------
	InCoin   *big.Int
	InEnergy *big.Int
	RhoIn    *big.Int
	RandIn   *big.Int
	SkIn     *big.Int
	PkIn     *big.Int
	PkOut    *big.Int
	EncKey   bls12377.G1Affine
	R        *big.Int
}

// BuildWitness construit une instance de CircuitTxRegister avec
// les bons champs public/privé et la renvoie.
func (ip *InputProverRegister) BuildWitness() (frontend.Circuit, error) {
	var c CircuitTxRegister

	// (1) champs PUBLIC du circuit
	c.CmIn = ip.CmIn
	for i := 0; i < 5; i++ {
		c.CAux[i] = ip.CAux[i]
	}
	c.GammaInCoins = ip.GammaInCoins
	c.GammaInEnergy = ip.GammaInEnergy
	c.Bid = ip.Bid

	c.G = sw_bls12377.NewG1Affine(ip.G)
	c.G_b = sw_bls12377.NewG1Affine(ip.G_b)
	c.G_r = sw_bls12377.NewG1Affine(ip.G_r)

	// (2) champs PRIVÉS
	c.InCoin = ip.InCoin
	c.InEnergy = ip.InEnergy
	c.RhoIn = ip.RhoIn
	c.RandIn = ip.RandIn
	c.SkIn = ip.SkIn
	c.PkIn = ip.PkIn
	c.PkOut = ip.PkOut
	c.EncKey = sw_bls12377.NewG1Affine(ip.EncKey)
	c.R = ip.R

	return &c, nil
}

// func (inp *InputProverRegister) BuildWitness() (frontend.Circuit, error) {
// 	var c CircuitTxRegister

// 	c.InCoin = inp.InCoin
// 	c.InEnergy = inp.InEnergy
// 	c.CmIn = inp.CmIn

// 	for k := 0; k < 5; k++ {
// 		c.CAux[k] = inp.CAux[k]
// 	}

// 	c.SkIn = inp.SkIn
// 	c.PkIn = inp.PkIn

// 	c.PkOut = inp.PkOut

// 	c.GammaInCoins = inp.GammaInCoins
// 	c.GammaInEnergy = inp.GammaInEnergy
// 	c.Bid = inp.Bid

// 	c.RhoIn = inp.RhoIn
// 	c.RandIn = inp.RandIn

// 	c.R = inp.R
// 	//c.B = new(big.Int).SetBytes(inp.B)
// 	c.G = sw_bls12377.NewG1Affine(inp.G)
// 	c.G_b = sw_bls12377.NewG1Affine(inp.G_b)
// 	c.G_r = sw_bls12377.NewG1Affine(inp.G_r)
// 	c.EncKey = sw_bls12377.NewG1Affine(inp.EncKey)

// 	return &c, nil
// }

func (inp *InputProverDefaultOneCoin) BuildWitness() (frontend.Circuit, error) {
	var c CircuitTxDefaultOneCoin
	// old
	c.OldCoin = inp.OldCoin
	c.OldEnergy = inp.OldEnergy
	c.CmOld = new(big.Int).SetBytes(inp.CmOld)
	c.SnOld = new(big.Int).SetBytes(inp.SnOld)
	c.PkOld = new(big.Int).SetBytes(inp.PkOld)

	c.SkOld = inp.SkOld
	c.RhoOld = inp.RhoOld
	c.RandOld = inp.RandOld
	// new
	c.NewCoin = inp.NewCoin
	c.NewEnergy = inp.NewEnergy
	c.CmNew = new(big.Int).SetBytes(inp.CmNew)

	for k := 0; k < 6; k++ {
		c.CNew[k] = inp.CNew[k]
	}

	c.PkNew = inp.PkNew
	c.RhoNew = inp.RhoNew
	c.RandNew = inp.RandNew

	c.R = new(big.Int).SetBytes(inp.R)
	//c.B = new(big.Int).SetBytes(inp.B)
	c.G = sw_bls12377.NewG1Affine(inp.G)
	c.G_b = sw_bls12377.NewG1Affine(inp.G_b)
	c.G_r = sw_bls12377.NewG1Affine(inp.G_r)
	c.EncKey = sw_bls12377.NewG1Affine(inp.EncKey)

	return &c, nil
}

// -----------------------------------------------------------------------------
// (5) TxResult, TxProverInputHighLevel, Transaction, ValidateTx
// -----------------------------------------------------------------------------

type TxResult struct {
	SnOld [2][]byte
	CmNew [2][]byte
	CNew  [2]Note
	Proof []byte

	// Pour la validation
	RhoNew  [2]*big.Int
	RandNew [2]*big.Int
	SkOld   [2][]byte
	RhoOld  [2]*big.Int
	RandOld [2]*big.Int
	PkNew   [2]*big.Int
}

type TxResultDefaultOneCoin struct {
	SnOld []byte
	CmNew []byte
	CNew  Note
	Proof []byte

	// Pour la validation
	RhoNew  *big.Int
	RandNew *big.Int
	SkOld   []byte
	RhoOld  *big.Int
	RandOld *big.Int
	PkNew   *big.Int
}

type TxResultDefaultNCoin struct {
	// Pour chaque coin, on stocke les valeurs spécifiques sous forme de slices.
	SnOld [][]byte // Le serial number pour chaque coin.
	CmNew [][]byte // Le commitment new pour chaque coin.
	CNew  []Note   // La note new pour chaque coin.
	Proof []byte   // La preuve globale de la transaction.

	// Pour la validation (chaque champ correspond aux données d'un coin)
	RhoNew  []*big.Int
	RandNew []*big.Int
	SkOld   [][]byte
	RhoOld  []*big.Int
	RandOld []*big.Int
	PkNew   []*big.Int
}

type TxResultRegister struct {
	CAux     [5][]byte
	tx       TxResultDefaultOneCoin
	ProofReg []byte
}

type TxProverInputHighLevel struct {
	OldNotes [2]Note
	OldSk    [2][]byte
	NewVals  [2]Gamma
	NewPk    [2][]byte
	EncKey   bls12377.G1Affine
	R        []byte
	//B        []byte
	G   bls12377.G1Affine
	G_b bls12377.G1Affine
	G_r bls12377.G1Affine
}

// Transaction => alg.1
func Transaction(inp TxProverInputHighLevel) TxResult {
	// 1) snOld[i] = MiMC(skOld[i], RhoOld[i]) hors-circuit
	var snOld [2][]byte
	for i := 0; i < 2; i++ {
		sn := CalcSerialMimc(inp.OldSk[i], inp.OldNotes[i].Rho)
		snOld[i] = sn
	}
	// 2) generer (rhoNew, randNew), cmNew, cNew
	var rhoNew [2]*big.Int
	var randNew [2]*big.Int
	var cmNew [2][]byte
	//var cNew [2][][]byte
	var cNew [2]Note

	for j := 0; j < 2; j++ {
		rhoNew[j] = RandBigInt()
		randNew[j] = RandBigInt()
		cm := Committment(inp.NewVals[j].Coins, inp.NewVals[j].Energy,
			rhoNew[j], randNew[j])
		cmNew[j] = cm
		encVal := BuildEncMimc(inp.EncKey, inp.NewPk[j],
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
	var ip InputProver
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

	return TxResult{
		SnOld: snOld,
		CmNew: cmNew,
		CNew:  [2]Note{cNew[0], cNew[1]},
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
}

// ValidateTx => on refait un InputProver + publicOnly => groth16.Verify
func ValidateTx(tx TxResult,
	old [2]Note,
	newVal [2]Gamma,
	G bls12377.G1Affine,
	G_b bls12377.G1Affine,
	G_r bls12377.G1Affine,
	vk groth16.VerifyingKey,
) bool {

	var ip InputProver
	// old
	for i := 0; i < 2; i++ {
		ip.OldCoins[i] = old[i].Value.Coins
		ip.OldEnergy[i] = old[i].Value.Energy
		ip.CmOld[i] = old[i].Cm
		ip.SnOld[i] = tx.SnOld[i]
		ip.PkOld[i] = old[i].PkOwner

		ip.SkOld[i] = new(big.Int).SetBytes(tx.SkOld[i])
		ip.RhoOld[i] = tx.RhoOld[i]
		ip.RandOld[i] = tx.RandOld[i]
	}
	// new
	for j := 0; j < 2; j++ {
		ip.NewCoins[j] = newVal[j].Coins
		ip.NewEnergy[j] = newVal[j].Energy
		ip.CmNew[j] = tx.CmNew[j]

		ip.CNew[j] = make([][]byte, 6)
		ip.CNew[j][0] = tx.CNew[j].PkOwner
		ip.CNew[j][1] = tx.CNew[j].Value.Coins.Bytes()
		ip.CNew[j][2] = tx.CNew[j].Value.Energy.Bytes()
		ip.CNew[j][3] = tx.CNew[j].Rho
		ip.CNew[j][4] = tx.CNew[j].Rand
		ip.CNew[j][5] = tx.CNew[j].Cm

		ip.PkNew[j] = tx.PkNew[j]
		ip.RhoNew[j] = tx.RhoNew[j]
		ip.RandNew[j] = tx.RandNew[j]
	}

	ip.G = G
	ip.G_b = G_b
	ip.G_r = G_r

	wc, _ := ip.BuildWitness()
	pubOnly, _ := frontend.NewWitness(wc, ecc.BW6_761.ScalarField(), frontend.PublicOnly())

	buf := bytes.NewReader(tx.Proof)
	p := groth16.NewProof(ecc.BW6_761)
	_, err := p.ReadFrom(buf)
	if err != nil {
		fmt.Println("invalid proof =>", err)
		return false
	}
	err = groth16.Verify(p, vk, pubOnly)
	if err != nil {
		fmt.Println("Verify fail =>", err)
		return false
	}
	return true
}

/*
CmIn          frontend.Variable    `gnark:",public"` // engagement d'InCoin+InEnergy
CAux          [5]frontend.Variable `gnark:",public"` // ciphertext "aux"
GammaInEnergy frontend.Variable    `gnark:",public"` // energy "in"
GammaInCoins  frontend.Variable    `gnark:",public"` // coin  "in"
Bid           frontend.Variable    `gnark:",public"` // enchère
G             sw_bls12377.G1Affine `gnark:",public"`
G_b           sw_bls12377.G1Affine `gnark:",public"`
G_r           sw_bls12377.G1Affine `gnark:",public"`
*/

func ValidateTxRegisterProof(
	tx TxResultDefaultOneCoin,
	old Note,
	newVal Gamma,
	G bls12377.G1Affine,
	G_b bls12377.G1Affine,
	G_r bls12377.G1Affine,
	vk groth16.VerifyingKey,
) bool {

	var ip InputProverDefaultOneCoin
	// old
	ip.OldCoin = old.Value.Coins
	ip.OldEnergy = old.Value.Energy
	ip.CmOld = old.Cm
	ip.SnOld = tx.SnOld
	ip.PkOld = old.PkOwner

	ip.SkOld = new(big.Int).SetBytes(tx.SkOld)
	ip.RhoOld = tx.RhoOld
	ip.RandOld = tx.RandOld
	// new
	ip.NewCoin = newVal.Coins
	ip.NewEnergy = newVal.Energy
	ip.CmNew = tx.CmNew

	ip.CNew = make([][]byte, 6)
	ip.CNew[0] = tx.CNew.PkOwner
	ip.CNew[1] = tx.CNew.Value.Coins.Bytes()
	ip.CNew[2] = tx.CNew.Value.Energy.Bytes()
	ip.CNew[3] = tx.CNew.Rho
	ip.CNew[4] = tx.CNew.Rand
	ip.CNew[5] = tx.CNew.Cm

	ip.PkNew = tx.PkNew
	ip.RhoNew = tx.RhoNew
	ip.RandNew = tx.RandNew

	ip.G = G
	ip.G_b = G_b
	ip.G_r = G_r

	wc, _ := ip.BuildWitness()
	pubOnly, _ := frontend.NewWitness(wc, ecc.BW6_761.ScalarField(), frontend.PublicOnly())

	buf := bytes.NewReader(tx.Proof)
	p := groth16.NewProof(ecc.BW6_761)
	_, err := p.ReadFrom(buf)
	if err != nil {
		fmt.Println("invalid proof =>", err)
		return false
	}
	err = groth16.Verify(p, vk, pubOnly)
	if err != nil {
		fmt.Println("Verify fail =>", err)
		return false
	}
	return true
}

func ValidateTxDefaultCoin(tx TxResultDefaultOneCoin,
	old Note,
	newVal Gamma,
	G bls12377.G1Affine,
	G_b bls12377.G1Affine,
	G_r bls12377.G1Affine,
	vk groth16.VerifyingKey,
) bool {

	var ip InputProverDefaultOneCoin
	// old
	ip.OldCoin = old.Value.Coins
	ip.OldEnergy = old.Value.Energy
	ip.CmOld = old.Cm
	ip.SnOld = tx.SnOld
	ip.PkOld = old.PkOwner

	ip.SkOld = new(big.Int).SetBytes(tx.SkOld)
	ip.RhoOld = tx.RhoOld
	ip.RandOld = tx.RandOld
	// new
	ip.NewCoin = newVal.Coins
	ip.NewEnergy = newVal.Energy
	ip.CmNew = tx.CmNew

	ip.CNew = make([][]byte, 6)
	ip.CNew[0] = tx.CNew.PkOwner
	ip.CNew[1] = tx.CNew.Value.Coins.Bytes()
	ip.CNew[2] = tx.CNew.Value.Energy.Bytes()
	ip.CNew[3] = tx.CNew.Rho
	ip.CNew[4] = tx.CNew.Rand
	ip.CNew[5] = tx.CNew.Cm

	ip.PkNew = tx.PkNew
	ip.RhoNew = tx.RhoNew
	ip.RandNew = tx.RandNew

	ip.G = G
	ip.G_b = G_b
	ip.G_r = G_r

	wc, _ := ip.BuildWitness()
	pubOnly, _ := frontend.NewWitness(wc, ecc.BW6_761.ScalarField(), frontend.PublicOnly())

	buf := bytes.NewReader(tx.Proof)
	p := groth16.NewProof(ecc.BW6_761)
	_, err := p.ReadFrom(buf)
	if err != nil {
		fmt.Println("invalid proof =>", err)
		return false
	}
	err = groth16.Verify(p, vk, pubOnly)
	if err != nil {
		fmt.Println("Verify fail =>", err)
		return false
	}
	return true
}

/*
CmIn          frontend.Variable    `gnark:",public"` // engagement d'InCoin+InEnergy
CAux          [5]frontend.Variable `gnark:",public"` // ciphertext "aux"
GammaInEnergy frontend.Variable    `gnark:",public"` // energy "in"
GammaInCoins  frontend.Variable    `gnark:",public"` // coin  "in"
Bid           frontend.Variable    `gnark:",public"` // enchère
G             sw_bls12377.G1Affine `gnark:",public"`
G_b           sw_bls12377.G1Affine `gnark:",public"`
G_r           sw_bls12377.G1Affine `gnark:",public"`
*/

func ValidateTxRegister(
	proofBytes []byte, // la preuve
	pubWitnessBytes []byte, // éventuellement le witness public
	Ip InputProverRegister,
	// ou alors, si on doit le reconstruire:
	cmIn []byte,
	cAux [5][]byte,
	gammaInCoins, gammaInEnergy, bid *big.Int,
	G, G_b, G_r bls12377.G1Affine,
	vk groth16.VerifyingKey,
) bool {

	// 1) relire la preuve
	// proof := groth16.NewProof(ecc.BW6_761)
	// if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
	// 	fmt.Println("invalid proof =>", err)
	// 	return false
	// }

	buf := bytes.NewReader(proofBytes)
	proof := groth16.NewProof(ecc.BW6_761)
	_, err := proof.ReadFrom(buf)
	if err != nil {
		fmt.Println("invalid proof =>", err)
		return false
	}

	// // 2) si on dispose du pubWitnessBytes, on l’utilise directement
	// if len(pubWitnessBytes) > 0 {
	// 	// 1) on crée un "circuit vide" adapté à la vérification.
	// 	var circuitPublic CircuitTxRegister // ou n'importe quel circuit

	// 	// 2) on construit le witness en mode "public only"
	// 	wPub, err := frontend.NewWitness(&circuitPublic, ecc.BW6_761.ScalarField(), frontend.PublicOnly())
	// 	if err != nil {
	// 		fmt.Println("Error building public witness =>", err)
	// 		return false
	// 	}

	// 	// 3) on lit les bytes publics
	// 	if _, err := wPub.ReadFrom(bytes.NewReader(pubWitnessBytes)); err != nil {
	// 		fmt.Println("Error reading public witness =>", err)
	// 		return false
	// 	}

	// 	// 4) on vérifie la preuve
	// 	if err := groth16.Verify(proof, vk, wPub); err != nil {
	// 		fmt.Println("proof verify =>", err)
	// 		return false
	// 	}
	// 	return true
	// }

	// 3) sinon, on RECONSTRUIT la partie publique
	// On se base sur InputProverRegister, mais en ignorant la partie privée.
	// => on va tout mettre à zéro pour la partie privée, et "cmIn, cAux, gamma, bid, G, G_b, G_r" pour la partie publique
	// var ip InputProverRegister

	// // remplir ip en public seulement
	// ip.CmIn = cmIn
	// ip.CAux = cAux
	// ip.GammaInCoins = gammaInCoins
	// ip.GammaInEnergy = gammaInEnergy
	// ip.Bid = bid
	// ip.G = G
	// ip.G_b = G_b
	// ip.G_r = G_r

	//  => le reste (InCoin, InEnergy, ...) reste nil, donc 0

	circuitFull, err := Ip.BuildWitness()
	if err != nil {
		fmt.Println("build witness =>", err)
		return false
	}
	// on extrait juste la partie publique
	wPub, err := frontend.NewWitness(circuitFull, ecc.BW6_761.ScalarField(), frontend.PublicOnly())
	if err != nil {
		fmt.Println("NewWitness =>", err)
		return false
	}

	// 4) vérification
	if err := groth16.Verify(proof, vk, wPub); err != nil {
		fmt.Println("Verify =>", err)
		return false
	}
	return true
}

// func ValidateTxRegister(
// 	tx TxResultDefaultOneCoin,
// 	CmIn []byte,
// 	CAux [5][]byte,
// 	GammaInEnergy *big.Int,
// 	GammaInCoins *big.Int,
// 	Bid *big.Int,
// 	G bls12377.G1Affine,
// 	G_b bls12377.G1Affine,
// 	G_r bls12377.G1Affine,
// 	vk groth16.VerifyingKey,
// 	PiReg []byte, // la preuve sérialisée
// 	PubW []byte, // le witness public (éventuellement)
// ) bool {

// 	//------------------------------------------------------------------
// 	// 1) Lecture de la preuve piReg depuis PiReg
// 	//------------------------------------------------------------------
// 	var proof groth16.Proof
// 	{
// 		buf := bytes.NewReader(PiReg)
// 		proofBW6 := groth16.NewProof(ecc.BW6_761) // structure vide
// 		if _, err := proofBW6.ReadFrom(buf); err != nil {
// 			fmt.Println("invalid proof =>", err)
// 			return false
// 		}
// 		proof = proofBW6
// 	}

// 	//------------------------------------------------------------------
// 	// 2) Approche "si PubW est fourni, on l’utilise directement"
// 	//------------------------------------------------------------------
// 	if len(PubW) > 0 {
// 		wPub, err := witness.NewPublic(ecc.BW6_761.ScalarField())
// 		if err != nil {
// 			fmt.Println("could not create new public witness =>", err)
// 			return false
// 		}
// 		// on relit PubW
// 		if _, err := wPub.ReadFrom(bytes.NewReader(PubW)); err != nil {
// 			fmt.Println("could not read public witness from PubW =>", err)
// 			return false
// 		}

// 		// on vérifie
// 		if err := groth16.Verify(proof, vk, wPub); err != nil {
// 			fmt.Println("Verify fail =>", err)
// 			return false
// 		}

// 		// Si tout va bien
// 		return true
// 	}

// 	//------------------------------------------------------------------
// 	// 3) Sinon, on RECONSTRUIT la partie publique localement
// 	//------------------------------------------------------------------
// 	//    => on utilise InputVerifierRegister pour décrire les
// 	//       variables publiques dont le circuit Register a besoin.
// 	//------------------------------------------------------------------
// 	var ip InputVerifierRegister

// 	// a) commitment d’entrée
// 	ip.CmIn = new(big.Int).SetBytes(CmIn)

// 	// b) les 5 blocs de ciphertext
// 	for k := 0; k < 5; k++ {
// 		ip.CAux[k] = new(big.Int).SetBytes(CAux[k])
// 	}

// 	// c) valeurs gammaIn, bid...
// 	ip.GammaInEnergy = GammaInEnergy
// 	ip.GammaInCoins = GammaInCoins
// 	ip.Bid = Bid

// 	// d) paramètres DH
// 	ip.G = G
// 	ip.G_b = G_b
// 	ip.G_r = G_r

// 	//------------------------------------------------------------------
// 	// 4) Construction du witness "complet", puis extraction de la partie publique
// 	//------------------------------------------------------------------
// 	wc, err := ip.BuildWitness()
// 	if err != nil {
// 		fmt.Println("BuildWitness() error =>", err)
// 		return false
// 	}
// 	pubOnly, err := frontend.NewWitness(wc, ecc.BW6_761.ScalarField(), frontend.PublicOnly())
// 	if err != nil {
// 		fmt.Println("error building public witness =>", err)
// 		return false
// 	}

// 	//------------------------------------------------------------------
// 	// 5) Vérification finale
// 	//------------------------------------------------------------------
// 	err = groth16.Verify(proof, vk, pubOnly)
// 	if err != nil {
// 		fmt.Println("Verify fail =>", err)
// 		return false
// 	}

// 	return true
// }

// func ValidateTxRegister(tx TxResultDefaultOneCoin,
// 	CmIn []byte,
// 	CAux [5][]byte,
// 	GammaInEnergy *big.Int,
// 	GammaInCoins *big.Int,
// 	Bid *big.Int,
// 	G bls12377.G1Affine,
// 	G_b bls12377.G1Affine,
// 	G_r bls12377.G1Affine,
// 	vk groth16.VerifyingKey,
// 	PiReg []byte,
// 	PubW []byte,
// ) bool {

// 	var ip InputVerifierRegister

// 	ip.CmIn = new(big.Int).SetBytes(CmIn)
// 	for k := 0; k < 5; k++ {
// 		ip.CAux[k] = new(big.Int).SetBytes(CAux[k])
// 	}

// 	ip.GammaInEnergy = GammaInEnergy
// 	ip.GammaInCoins = GammaInCoins

// 	ip.Bid = Bid

// 	ip.G = G
// 	ip.G_b = G_b
// 	ip.G_r = G_r

// 	//HELLO

// 	wc, _ := ip.BuildWitness()
// 	pubOnly, _ := frontend.NewWitness(wc, ecc.BW6_761.ScalarField(), frontend.PublicOnly())

// 	//buf := bytes.NewReader(tx.Proof)
// 	buf := bytes.NewReader(PiReg)
// 	p := groth16.NewProof(ecc.BW6_761)
// 	_, err := p.ReadFrom(buf)
// 	if err != nil {
// 		fmt.Println("invalid proof =>", err)
// 		return false
// 	}
// 	err = groth16.Verify(p, vk, pubOnly)
// 	if err != nil {
// 		fmt.Println("Verify fail =>", err)
// 		return false
// 	}

// 	// 2) Génération de preuve de la transaction de registration

// 	return true
// }

// -----------------------------------------------------------------------------
// (6) loadOrGenerateKeys : PK, VK synchronisés
// -----------------------------------------------------------------------------

var (
	globalCCS constraint.ConstraintSystem
	globalPK  groth16.ProvingKey
	globalVK  groth16.VerifyingKey
)

func LoadOrGenerateKeys(circuit_type string) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey) {
	logger := log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	switch circuit_type {
	case "default":
		if _, err := os.Stat("_run_default"); os.IsNotExist(err) {
			os.Mkdir("_run_default", 0755)
		}
		// 1) Charger/Compiler circuit
		cssFile := "_run_default/css"
		var c CircuitTxMulti
		if _, err := os.Stat(cssFile); err == nil {
			d, _ := os.ReadFile(cssFile)
			ccs := groth16.NewCS(ecc.BW6_761)
			ccs.ReadFrom(bytes.NewReader(d))
			logger.Info().Str("cssFile", cssFile).Msg("Circuit loaded from disk")
			globalCCS = ccs
		} else {
			//fmt.Println("Compiling circuit =>", cssFile)
			ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &c)
			if err != nil {
				panic(err)
			}
			var buf bytes.Buffer
			ccs.WriteTo(&buf)
			os.WriteFile(cssFile, buf.Bytes(), 0644)
			globalCCS = ccs
		}
		// 2) Charger ou générer pk+vk
		pkFile := "_run_default/zk_pk"
		vkFile := "_run_default/zk_vk"
		if fileExists(pkFile) && fileExists(vkFile) {

			logger.Info().Str("vkFile", vkFile).Str("pkFile", pkFile).Msg("Loading keys from disk")
			pkData, _ := os.ReadFile(pkFile)
			vkData, _ := os.ReadFile(vkFile)

			pk := groth16.NewProvingKey(ecc.BW6_761)
			vk := groth16.NewVerifyingKey(ecc.BW6_761)
			_, err := pk.ReadFrom(bytes.NewReader(pkData))
			if err != nil {
				panic(err)
			}
			_, err = vk.ReadFrom(bytes.NewReader(vkData))
			if err != nil {
				panic(err)
			}
			globalPK = pk
			globalVK = vk
		} else {
			logger.Info().Str("vkFile", vkFile).Str("pkFile", pkFile).Msg("Generating keys")
			//fmt.Println("Generating pk, vk =>", pkFile, vkFile)
			pk, vk, err := groth16.Setup(globalCCS)
			if err != nil {
				panic(err)
			}
			var bufPK bytes.Buffer
			pk.WriteTo(&bufPK)
			os.WriteFile(pkFile, bufPK.Bytes(), 0644)
			var bufVK bytes.Buffer
			vk.WriteTo(&bufVK)
			os.WriteFile(vkFile, bufVK.Bytes(), 0644)

			globalPK = pk
			globalVK = vk
		}
	case "oneCoin":
		if _, err := os.Stat("_run_oneCoin"); os.IsNotExist(err) {
			os.Mkdir("_run_oneCoin", 0755)
		}
		// 1) Charger/Compiler circuit
		cssFile := "_run_oneCoin/css"
		var c CircuitTxDefaultOneCoin
		if _, err := os.Stat(cssFile); err == nil {
			d, _ := os.ReadFile(cssFile)
			ccs := groth16.NewCS(ecc.BW6_761)
			ccs.ReadFrom(bytes.NewReader(d))
			logger.Info().Str("cssFile", cssFile).Msg("Circuit loaded from disk")
			globalCCS = ccs
		} else {
			//fmt.Println("Compiling circuit =>", cssFile)
			ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &c)
			if err != nil {
				panic(err)
			}
			var buf bytes.Buffer
			ccs.WriteTo(&buf)
			os.WriteFile(cssFile, buf.Bytes(), 0644)
			globalCCS = ccs
		}
		// 2) Charger ou générer pk+vk
		pkFile := "_run_oneCoin/zk_pk"
		vkFile := "_run_oneCoin/zk_vk"
		if fileExists(pkFile) && fileExists(vkFile) {

			logger.Info().Str("vkFile", vkFile).Str("pkFile", pkFile).Msg("Loading keys from disk")
			pkData, _ := os.ReadFile(pkFile)
			vkData, _ := os.ReadFile(vkFile)

			pk := groth16.NewProvingKey(ecc.BW6_761)
			vk := groth16.NewVerifyingKey(ecc.BW6_761)
			_, err := pk.ReadFrom(bytes.NewReader(pkData))
			if err != nil {
				panic(err)
			}
			_, err = vk.ReadFrom(bytes.NewReader(vkData))
			if err != nil {
				panic(err)
			}
			globalPK = pk
			globalVK = vk
		} else {
			logger.Info().Str("vkFile", vkFile).Str("pkFile", pkFile).Msg("Generating keys")
			//fmt.Println("Generating pk, vk =>", pkFile, vkFile)
			pk, vk, err := groth16.Setup(globalCCS)
			if err != nil {
				panic(err)
			}
			var bufPK bytes.Buffer
			pk.WriteTo(&bufPK)
			os.WriteFile(pkFile, bufPK.Bytes(), 0644)
			var bufVK bytes.Buffer
			vk.WriteTo(&bufVK)
			os.WriteFile(vkFile, bufVK.Bytes(), 0644)

			globalPK = pk
			globalVK = vk
		}
	case "2coin":
		if _, err := os.Stat("_run_2coin"); os.IsNotExist(err) {
			os.Mkdir("_run_2coin", 0755)
		}
		// 1) Charger/Compiler circuit
		cssFile := "_run_2coin/css"
		var c CircuitTxDefaultTwoCoin
		if _, err := os.Stat(cssFile); err == nil {
			d, _ := os.ReadFile(cssFile)
			ccs := groth16.NewCS(ecc.BW6_761)
			ccs.ReadFrom(bytes.NewReader(d))
			logger.Info().Str("cssFile", cssFile).Msg("Circuit loaded from disk")
			globalCCS = ccs
		} else {
			//fmt.Println("Compiling circuit =>", cssFile)
			ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &c)
			if err != nil {
				panic(err)
			}
			var buf bytes.Buffer
			ccs.WriteTo(&buf)
			os.WriteFile(cssFile, buf.Bytes(), 0644)
			globalCCS = ccs
		}
		// 2) Charger ou générer pk+vk
		pkFile := "_run_2coin/zk_pk"
		vkFile := "_run_2coin/zk_vk"
		if fileExists(pkFile) && fileExists(vkFile) {

			logger.Info().Str("vkFile", vkFile).Str("pkFile", pkFile).Msg("Loading keys from disk")
			pkData, _ := os.ReadFile(pkFile)
			vkData, _ := os.ReadFile(vkFile)

			pk := groth16.NewProvingKey(ecc.BW6_761)
			vk := groth16.NewVerifyingKey(ecc.BW6_761)
			_, err := pk.ReadFrom(bytes.NewReader(pkData))
			if err != nil {
				panic(err)
			}
			_, err = vk.ReadFrom(bytes.NewReader(vkData))
			if err != nil {
				panic(err)
			}
			globalPK = pk
			globalVK = vk
		} else {
			logger.Info().Str("vkFile", vkFile).Str("pkFile", pkFile).Msg("Generating keys")
			//fmt.Println("Generating pk, vk =>", pkFile, vkFile)
			pk, vk, err := groth16.Setup(globalCCS)
			if err != nil {
				panic(err)
			}
			var bufPK bytes.Buffer
			pk.WriteTo(&bufPK)
			os.WriteFile(pkFile, bufPK.Bytes(), 0644)
			var bufVK bytes.Buffer
			vk.WriteTo(&bufVK)
			os.WriteFile(vkFile, bufVK.Bytes(), 0644)

			globalPK = pk
			globalVK = vk
		}
	case "f2":
		if _, err := os.Stat("_run_F2"); os.IsNotExist(err) {
			os.Mkdir("_run_F2", 0755)
		}
		// 1) Charger/Compiler circuit
		cssFile := "_run_F2/css"
		var c CircuitTxF2
		if _, err := os.Stat(cssFile); err == nil {
			d, _ := os.ReadFile(cssFile)
			ccs := groth16.NewCS(ecc.BW6_761)
			ccs.ReadFrom(bytes.NewReader(d))
			logger.Info().Str("cssFile", cssFile).Msg("Circuit loaded from disk")
			globalCCS = ccs
		} else {
			//fmt.Println("Compiling circuit =>", cssFile)
			ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &c)
			if err != nil {
				panic(err)
			}
			var buf bytes.Buffer
			ccs.WriteTo(&buf)
			os.WriteFile(cssFile, buf.Bytes(), 0644)
			globalCCS = ccs
		}
		// 2) Charger ou générer pk+vk
		pkFile := "_run_F2/zk_pk"
		vkFile := "_run_F2/zk_vk"
		if fileExists(pkFile) && fileExists(vkFile) {

			logger.Info().Str("vkFile", vkFile).Str("pkFile", pkFile).Msg("Loading keys from disk")
			pkData, _ := os.ReadFile(pkFile)
			vkData, _ := os.ReadFile(vkFile)

			pk := groth16.NewProvingKey(ecc.BW6_761)
			vk := groth16.NewVerifyingKey(ecc.BW6_761)
			_, err := pk.ReadFrom(bytes.NewReader(pkData))
			if err != nil {
				panic(err)
			}
			_, err = vk.ReadFrom(bytes.NewReader(vkData))
			if err != nil {
				panic(err)
			}
			globalPK = pk
			globalVK = vk
		} else {
			logger.Info().Str("vkFile", vkFile).Str("pkFile", pkFile).Msg("Generating keys")
			//fmt.Println("Generating pk, vk =>", pkFile, vkFile)
			pk, vk, err := groth16.Setup(globalCCS)
			if err != nil {
				panic(err)
			}
			var bufPK bytes.Buffer
			pk.WriteTo(&bufPK)
			os.WriteFile(pkFile, bufPK.Bytes(), 0644)
			var bufVK bytes.Buffer
			vk.WriteTo(&bufVK)
			os.WriteFile(vkFile, bufVK.Bytes(), 0644)

			globalPK = pk
			globalVK = vk
		}
	case "f3":
		if _, err := os.Stat("_run_F3"); os.IsNotExist(err) {
			os.Mkdir("_run_F3", 0755)
		}
		// 1) Charger/Compiler circuit
		cssFile := "_run_F3/css"
		var c CircuitTxF3
		if _, err := os.Stat(cssFile); err == nil {
			d, _ := os.ReadFile(cssFile)
			ccs := groth16.NewCS(ecc.BW6_761)
			ccs.ReadFrom(bytes.NewReader(d))
			logger.Info().Str("cssFile", cssFile).Msg("Circuit loaded from disk")
			globalCCS = ccs
		} else {
			//fmt.Println("Compiling circuit =>", cssFile)
			ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &c)
			if err != nil {
				panic(err)
			}
			var buf bytes.Buffer
			ccs.WriteTo(&buf)
			os.WriteFile(cssFile, buf.Bytes(), 0644)
			globalCCS = ccs
		}
		// 2) Charger ou générer pk+vk
		pkFile := "_run_F3/zk_pk"
		vkFile := "_run_F3/zk_vk"
		if fileExists(pkFile) && fileExists(vkFile) {

			logger.Info().Str("vkFile", vkFile).Str("pkFile", pkFile).Msg("Loading keys from disk")
			pkData, _ := os.ReadFile(pkFile)
			vkData, _ := os.ReadFile(vkFile)

			pk := groth16.NewProvingKey(ecc.BW6_761)
			vk := groth16.NewVerifyingKey(ecc.BW6_761)
			_, err := pk.ReadFrom(bytes.NewReader(pkData))
			if err != nil {
				panic(err)
			}
			_, err = vk.ReadFrom(bytes.NewReader(vkData))
			if err != nil {
				panic(err)
			}
			globalPK = pk
			globalVK = vk
		} else {
			logger.Info().Str("vkFile", vkFile).Str("pkFile", pkFile).Msg("Generating keys")
			//fmt.Println("Generating pk, vk =>", pkFile, vkFile)
			pk, vk, err := groth16.Setup(globalCCS)
			if err != nil {
				panic(err)
			}
			var bufPK bytes.Buffer
			pk.WriteTo(&bufPK)
			os.WriteFile(pkFile, bufPK.Bytes(), 0644)
			var bufVK bytes.Buffer
			vk.WriteTo(&bufVK)
			os.WriteFile(vkFile, bufVK.Bytes(), 0644)

			globalPK = pk
			globalVK = vk
		}

	case "3coin":
		if _, err := os.Stat("_run_3coin"); os.IsNotExist(err) {
			os.Mkdir("_run_3coin", 0755)
		}
		// 1) Charger/Compiler circuit
		cssFile := "_run_3coin/css"
		var c CircuitTxDefault3Coin
		if _, err := os.Stat(cssFile); err == nil {
			d, _ := os.ReadFile(cssFile)
			ccs := groth16.NewCS(ecc.BW6_761)
			ccs.ReadFrom(bytes.NewReader(d))
			logger.Info().Str("cssFile", cssFile).Msg("Circuit loaded from disk")
			globalCCS = ccs
		} else {
			//fmt.Println("Compiling circuit =>", cssFile)
			ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &c)
			if err != nil {
				panic(err)
			}
			var buf bytes.Buffer
			ccs.WriteTo(&buf)
			os.WriteFile(cssFile, buf.Bytes(), 0644)
			globalCCS = ccs
		}
		// 2) Charger ou générer pk+vk
		pkFile := "_run_3coin/zk_pk"
		vkFile := "_run_3coin/zk_vk"
		if fileExists(pkFile) && fileExists(vkFile) {

			logger.Info().Str("vkFile", vkFile).Str("pkFile", pkFile).Msg("Loading keys from disk")
			pkData, _ := os.ReadFile(pkFile)
			vkData, _ := os.ReadFile(vkFile)

			pk := groth16.NewProvingKey(ecc.BW6_761)
			vk := groth16.NewVerifyingKey(ecc.BW6_761)
			_, err := pk.ReadFrom(bytes.NewReader(pkData))
			if err != nil {
				panic(err)
			}
			_, err = vk.ReadFrom(bytes.NewReader(vkData))
			if err != nil {
				panic(err)
			}
			globalPK = pk
			globalVK = vk
		} else {
			logger.Info().Str("vkFile", vkFile).Str("pkFile", pkFile).Msg("Generating keys")
			//fmt.Println("Generating pk, vk =>", pkFile, vkFile)
			pk, vk, err := groth16.Setup(globalCCS)
			if err != nil {
				panic(err)
			}
			var bufPK bytes.Buffer
			pk.WriteTo(&bufPK)
			os.WriteFile(pkFile, bufPK.Bytes(), 0644)
			var bufVK bytes.Buffer
			vk.WriteTo(&bufVK)
			os.WriteFile(vkFile, bufVK.Bytes(), 0644)

			globalPK = pk
			globalVK = vk
		}
	case "register":
		if _, err := os.Stat("_run_register"); os.IsNotExist(err) {
			os.Mkdir("_run_register", 0755)
		}
		// 1) Charger/Compiler circuit
		cssFile := "_run_register/css"
		var c CircuitTxRegister
		if _, err := os.Stat(cssFile); err == nil {
			d, _ := os.ReadFile(cssFile)
			ccs := groth16.NewCS(ecc.BW6_761)
			ccs.ReadFrom(bytes.NewReader(d))
			logger.Info().Str("cssFile", cssFile).Msg("Circuit loaded from disk")
			globalCCS = ccs
		} else {
			//fmt.Println("Compiling circuit =>", cssFile)
			ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &c)
			if err != nil {
				panic(err)
			}
			var buf bytes.Buffer
			ccs.WriteTo(&buf)
			os.WriteFile(cssFile, buf.Bytes(), 0644)
			globalCCS = ccs
		}
		// 2) Charger ou générer pk+vk
		pkFile := "_run_register/zk_pk"
		vkFile := "_run_register/zk_vk"
		if fileExists(pkFile) && fileExists(vkFile) {

			logger.Info().Str("vkFile", vkFile).Str("pkFile", pkFile).Msg("Loading keys from disk")
			pkData, _ := os.ReadFile(pkFile)
			vkData, _ := os.ReadFile(vkFile)

			pk := groth16.NewProvingKey(ecc.BW6_761)
			vk := groth16.NewVerifyingKey(ecc.BW6_761)
			_, err := pk.ReadFrom(bytes.NewReader(pkData))
			if err != nil {
				panic(err)
			}
			_, err = vk.ReadFrom(bytes.NewReader(vkData))
			if err != nil {
				panic(err)
			}
			globalPK = pk
			globalVK = vk
		} else {
			logger.Info().Str("vkFile", vkFile).Str("pkFile", pkFile).Msg("Generating keys")
			//fmt.Println("Generating pk, vk =>", pkFile, vkFile)
			pk, vk, err := groth16.Setup(globalCCS)
			if err != nil {
				panic(err)
			}
			var bufPK bytes.Buffer
			pk.WriteTo(&bufPK)
			os.WriteFile(pkFile, bufPK.Bytes(), 0644)
			var bufVK bytes.Buffer
			vk.WriteTo(&bufVK)
			os.WriteFile(vkFile, bufVK.Bytes(), 0644)

			globalPK = pk
			globalVK = vk
		}
	case "f1":
		if _, err := os.Stat("_run_F1"); os.IsNotExist(err) {
			os.Mkdir("_run_F1", 0755)
		}
		// 1) Charger/Compiler circuit
		cssFile := "_run_F1/css"
		var c CircuitTxF1
		if _, err := os.Stat(cssFile); err == nil {
			d, _ := os.ReadFile(cssFile)
			ccs := groth16.NewCS(ecc.BW6_761)
			ccs.ReadFrom(bytes.NewReader(d))
			logger.Info().Str("cssFile", cssFile).Msg("Circuit loaded from disk")
			globalCCS = ccs
		} else {
			//fmt.Println("Compiling circuit =>", cssFile)
			ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &c)
			if err != nil {
				panic(err)
			}
			var buf bytes.Buffer
			ccs.WriteTo(&buf)
			os.WriteFile(cssFile, buf.Bytes(), 0644)
			globalCCS = ccs
		}
		// 2) Charger ou générer pk+vk
		pkFile := "_run_F1/zk_pk"
		vkFile := "_run_F1/zk_vk"
		if fileExists(pkFile) && fileExists(vkFile) {

			logger.Info().Str("vkFile", vkFile).Str("pkFile", pkFile).Msg("Loading keys from disk")
			pkData, _ := os.ReadFile(pkFile)
			vkData, _ := os.ReadFile(vkFile)

			pk := groth16.NewProvingKey(ecc.BW6_761)
			vk := groth16.NewVerifyingKey(ecc.BW6_761)
			_, err := pk.ReadFrom(bytes.NewReader(pkData))
			if err != nil {
				panic(err)
			}
			_, err = vk.ReadFrom(bytes.NewReader(vkData))
			if err != nil {
				panic(err)
			}
			globalPK = pk
			globalVK = vk
		} else {
			logger.Info().Str("vkFile", vkFile).Str("pkFile", pkFile).Msg("Generating keys")
			//fmt.Println("Generating pk, vk =>", pkFile, vkFile)
			pk, vk, err := groth16.Setup(globalCCS)
			if err != nil {
				panic(err)
			}
			var bufPK bytes.Buffer
			pk.WriteTo(&bufPK)
			os.WriteFile(pkFile, bufPK.Bytes(), 0644)
			var bufVK bytes.Buffer
			vk.WriteTo(&bufVK)
			os.WriteFile(vkFile, bufVK.Bytes(), 0644)

			globalPK = pk
			globalVK = vk
		}
	case "draw":
		if _, err := os.Stat("_run_draw"); os.IsNotExist(err) {
			os.Mkdir("_run_draw", 0755)
		}
		// 1) Charger/Compiler circuit
		cssFile := "_run_draw/css"
		var c CircuitWithdraw
		if _, err := os.Stat(cssFile); err == nil {
			d, _ := os.ReadFile(cssFile)
			ccs := groth16.NewCS(ecc.BW6_761)
			ccs.ReadFrom(bytes.NewReader(d))
			logger.Info().Str("cssFile", cssFile).Msg("Circuit loaded from disk")
			globalCCS = ccs
		} else {
			//fmt.Println("Compiling circuit =>", cssFile)
			ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &c)
			if err != nil {
				panic(err)
			}
			var buf bytes.Buffer
			ccs.WriteTo(&buf)
			os.WriteFile(cssFile, buf.Bytes(), 0644)
			globalCCS = ccs
		}
		// 2) Charger ou générer pk+vk
		pkFile := "_run_draw/zk_pk"
		vkFile := "_run_draw/zk_vk"
		if fileExists(pkFile) && fileExists(vkFile) {

			logger.Info().Str("vkFile", vkFile).Str("pkFile", pkFile).Msg("Loading keys from disk")
			pkData, _ := os.ReadFile(pkFile)
			vkData, _ := os.ReadFile(vkFile)

			pk := groth16.NewProvingKey(ecc.BW6_761)
			vk := groth16.NewVerifyingKey(ecc.BW6_761)
			_, err := pk.ReadFrom(bytes.NewReader(pkData))
			if err != nil {
				panic(err)
			}
			_, err = vk.ReadFrom(bytes.NewReader(vkData))
			if err != nil {
				panic(err)
			}
			globalPK = pk
			globalVK = vk
		} else {
			logger.Info().Str("vkFile", vkFile).Str("pkFile", pkFile).Msg("Generating keys")
			//fmt.Println("Generating pk, vk =>", pkFile, vkFile)
			pk, vk, err := groth16.Setup(globalCCS)
			if err != nil {
				panic(err)
			}
			var bufPK bytes.Buffer
			pk.WriteTo(&bufPK)
			os.WriteFile(pkFile, bufPK.Bytes(), 0644)
			var bufVK bytes.Buffer
			vk.WriteTo(&bufVK)
			os.WriteFile(vkFile, bufVK.Bytes(), 0644)

			globalPK = pk
			globalVK = vk
		}

	}

	return globalCCS, globalPK, globalVK
}

func fileExists(fname string) bool {
	if _, err := os.Stat(fname); err == nil {
		return true
	}
	return false
}

//////////////

type CircuitTxDefault3Coin struct {
	// === Coin 0 ===
	OldCoin0   frontend.Variable `gnark:",public"`
	OldEnergy0 frontend.Variable `gnark:",public"`
	CmOld0     frontend.Variable `gnark:",public"`
	SnOld0     frontend.Variable `gnark:",public"` // PRF_{sk}(rho)
	PkOld0     frontend.Variable `gnark:",public"`

	NewCoin0   frontend.Variable    `gnark:",public"`
	NewEnergy0 frontend.Variable    `gnark:",public"`
	CmNew0     frontend.Variable    `gnark:",public"`
	CNew0      [6]frontend.Variable `gnark:",public"`

	SkOld0   frontend.Variable
	RhoOld0  frontend.Variable
	RandOld0 frontend.Variable

	PkNew0   frontend.Variable
	RhoNew0  frontend.Variable
	RandNew0 frontend.Variable

	// === Coin 1 ===
	OldCoin1   frontend.Variable `gnark:",public"`
	OldEnergy1 frontend.Variable `gnark:",public"`
	CmOld1     frontend.Variable `gnark:",public"`
	SnOld1     frontend.Variable `gnark:",public"`
	PkOld1     frontend.Variable `gnark:",public"`

	NewCoin1   frontend.Variable    `gnark:",public"`
	NewEnergy1 frontend.Variable    `gnark:",public"`
	CmNew1     frontend.Variable    `gnark:",public"`
	CNew1      [6]frontend.Variable `gnark:",public"`

	SkOld1   frontend.Variable
	RhoOld1  frontend.Variable
	RandOld1 frontend.Variable

	PkNew1   frontend.Variable
	RhoNew1  frontend.Variable
	RandNew1 frontend.Variable

	// === Coin 2 ===
	OldCoin2   frontend.Variable `gnark:",public"`
	OldEnergy2 frontend.Variable `gnark:",public"`
	CmOld2     frontend.Variable `gnark:",public"`
	SnOld2     frontend.Variable `gnark:",public"`
	PkOld2     frontend.Variable `gnark:",public"`

	NewCoin2   frontend.Variable    `gnark:",public"`
	NewEnergy2 frontend.Variable    `gnark:",public"`
	CmNew2     frontend.Variable    `gnark:",public"`
	CNew2      [6]frontend.Variable `gnark:",public"`

	SkOld2   frontend.Variable
	RhoOld2  frontend.Variable
	RandOld2 frontend.Variable

	PkNew2   frontend.Variable
	RhoNew2  frontend.Variable
	RandNew2 frontend.Variable

	// === Paramètres pour chaque coin ===
	// Coin 0
	R0      frontend.Variable
	G0      sw_bls12377.G1Affine `gnark:",public"`
	G_b0    sw_bls12377.G1Affine `gnark:",public"`
	G_r0    sw_bls12377.G1Affine `gnark:",public"`
	EncKey0 sw_bls12377.G1Affine

	// Coin 1
	R1      frontend.Variable
	G1      sw_bls12377.G1Affine `gnark:",public"`
	G_b1    sw_bls12377.G1Affine `gnark:",public"`
	G_r1    sw_bls12377.G1Affine `gnark:",public"`
	EncKey1 sw_bls12377.G1Affine

	// Coin 2
	R2      frontend.Variable
	G2      sw_bls12377.G1Affine `gnark:",public"`
	G_b2    sw_bls12377.G1Affine `gnark:",public"`
	G_r2    sw_bls12377.G1Affine `gnark:",public"`
	EncKey2 sw_bls12377.G1Affine
}

func (c *CircuitTxDefault3Coin) Define(api frontend.API) error {
	// ----- Pour le coin 0 -----
	hasher0, _ := mimc.NewMiMC(api)
	hasher0.Reset()
	hasher0.Write(c.OldCoin0)
	hasher0.Write(c.OldEnergy0)
	hasher0.Write(c.RhoOld0)
	hasher0.Write(c.RandOld0)
	cm0 := hasher0.Sum()
	api.AssertIsEqual(c.CmOld0, cm0)

	snComputed0 := PRF(api, c.SkOld0, c.RhoOld0)
	api.AssertIsEqual(c.SnOld0, snComputed0)

	hasher0.Reset()
	hasher0.Write(c.NewCoin0)
	hasher0.Write(c.NewEnergy0)
	hasher0.Write(c.RhoNew0)
	hasher0.Write(c.RandNew0)
	cmNew0 := hasher0.Sum()
	api.AssertIsEqual(c.CmNew0, cmNew0)

	encVal0 := EncZK(api, c.PkNew0, c.NewCoin0, c.NewEnergy0, c.RhoNew0, c.RandNew0, c.CmNew0, c.EncKey0)
	for i := 0; i < 6; i++ {
		api.AssertIsEqual(c.CNew0[i], encVal0[i])
	}

	// ----- Pour le coin 1 -----
	hasher1, _ := mimc.NewMiMC(api)
	hasher1.Reset()
	hasher1.Write(c.OldCoin1)
	hasher1.Write(c.OldEnergy1)
	hasher1.Write(c.RhoOld1)
	hasher1.Write(c.RandOld1)
	cm1 := hasher1.Sum()
	api.AssertIsEqual(c.CmOld1, cm1)

	snComputed1 := PRF(api, c.SkOld1, c.RhoOld1)
	api.AssertIsEqual(c.SnOld1, snComputed1)

	hasher1.Reset()
	hasher1.Write(c.NewCoin1)
	hasher1.Write(c.NewEnergy1)
	hasher1.Write(c.RhoNew1)
	hasher1.Write(c.RandNew1)
	cmNew1 := hasher1.Sum()
	api.AssertIsEqual(c.CmNew1, cmNew1)

	encVal1 := EncZK(api, c.PkNew1, c.NewCoin1, c.NewEnergy1, c.RhoNew1, c.RandNew1, c.CmNew1, c.EncKey1)
	for i := 0; i < 6; i++ {
		api.AssertIsEqual(c.CNew1[i], encVal1[i])
	}

	// ----- Pour le coin 2 -----
	hasher2, _ := mimc.NewMiMC(api)
	hasher2.Reset()
	hasher2.Write(c.OldCoin2)
	hasher2.Write(c.OldEnergy2)
	hasher2.Write(c.RhoOld2)
	hasher2.Write(c.RandOld2)
	cm2 := hasher2.Sum()
	api.AssertIsEqual(c.CmOld2, cm2)

	snComputed2 := PRF(api, c.SkOld2, c.RhoOld2)
	api.AssertIsEqual(c.SnOld2, snComputed2)

	hasher2.Reset()
	hasher2.Write(c.NewCoin2)
	hasher2.Write(c.NewEnergy2)
	hasher2.Write(c.RhoNew2)
	hasher2.Write(c.RandNew2)
	cmNew2 := hasher2.Sum()
	api.AssertIsEqual(c.CmNew2, cmNew2)

	encVal2 := EncZK(api, c.PkNew2, c.NewCoin2, c.NewEnergy2, c.RhoNew2, c.RandNew2, c.CmNew2, c.EncKey2)
	for i := 0; i < 6; i++ {
		api.AssertIsEqual(c.CNew2[i], encVal2[i])
	}

	// ----- Conservation globale -----
	totalOldCoin := api.Add(api.Add(c.OldCoin0, c.OldCoin1), c.OldCoin2)
	totalNewCoin := api.Add(api.Add(c.NewCoin0, c.NewCoin1), c.NewCoin2)
	api.AssertIsEqual(totalOldCoin, totalNewCoin)

	totalOldEnergy := api.Add(api.Add(c.OldEnergy0, c.OldEnergy1), c.OldEnergy2)
	totalNewEnergy := api.Add(api.Add(c.NewEnergy0, c.NewEnergy1), c.NewEnergy2)
	api.AssertIsEqual(totalOldEnergy, totalNewEnergy)

	// ----- Vérifications additionnelles -----
	// Pour le coin 0 : (G^r)^b == EncKey0
	G_r_b0 := new(sw_bls12377.G1Affine)
	G_r_b0.ScalarMul(api, c.G_b0, c.R0)
	api.AssertIsEqual(c.EncKey0.X, G_r_b0.X)
	api.AssertIsEqual(c.EncKey0.Y, G_r_b0.Y)

	// Pour le coin 1
	G_r_b1 := new(sw_bls12377.G1Affine)
	G_r_b1.ScalarMul(api, c.G_b1, c.R1)
	api.AssertIsEqual(c.EncKey1.X, G_r_b1.X)
	api.AssertIsEqual(c.EncKey1.Y, G_r_b1.Y)

	// Pour le coin 2
	G_r_b2 := new(sw_bls12377.G1Affine)
	G_r_b2.ScalarMul(api, c.G_b2, c.R2)
	api.AssertIsEqual(c.EncKey2.X, G_r_b2.X)
	api.AssertIsEqual(c.EncKey2.Y, G_r_b2.Y)

	// Vérification que (G^r) == G_r pour chaque coin
	G_r0 := new(sw_bls12377.G1Affine)
	G_r0.ScalarMul(api, c.G0, c.R0)
	api.AssertIsEqual(c.G_r0.X, G_r0.X)
	api.AssertIsEqual(c.G_r0.Y, G_r0.Y)

	G_r1 := new(sw_bls12377.G1Affine)
	G_r1.ScalarMul(api, c.G1, c.R1)
	api.AssertIsEqual(c.G_r1.X, G_r1.X)
	api.AssertIsEqual(c.G_r1.Y, G_r1.Y)

	G_r2 := new(sw_bls12377.G1Affine)
	G_r2.ScalarMul(api, c.G2, c.R2)
	api.AssertIsEqual(c.G_r2.X, G_r2.X)
	api.AssertIsEqual(c.G_r2.Y, G_r2.Y)

	// Vérification de la dérivation de la clé publique pour chaque coin : PkOld = MiMC(SkOld)
	hasher0.Reset()
	hasher0.Write(c.SkOld0)
	pkOldComputed0 := hasher0.Sum()
	api.AssertIsEqual(c.PkOld0, pkOldComputed0)

	hasher1.Reset()
	hasher1.Write(c.SkOld1)
	pkOldComputed1 := hasher1.Sum()
	api.AssertIsEqual(c.PkOld1, pkOldComputed1)

	hasher2.Reset()
	hasher2.Write(c.SkOld2)
	pkOldComputed2 := hasher2.Sum()
	api.AssertIsEqual(c.PkOld2, pkOldComputed2)

	return nil
}

func (inp *InputProverDefaultNCoin) BuildWitness3() (frontend.Circuit, error) {
	var c CircuitTxDefault3Coin

	// --- Remplissage pour le coin 0 ---
	c.OldCoin0 = inp.OldCoin[0]
	c.OldEnergy0 = inp.OldEnergy[0]
	c.CmOld0 = new(big.Int).SetBytes(inp.CmOld[0])
	c.SnOld0 = new(big.Int).SetBytes(inp.SnOld[0])
	c.PkOld0 = new(big.Int).SetBytes(inp.PkOld[0])
	c.SkOld0 = inp.SkOld[0]
	c.RhoOld0 = inp.RhoOld[0]
	c.RandOld0 = inp.RandOld[0]

	c.NewCoin0 = inp.NewCoin[0]
	c.NewEnergy0 = inp.NewEnergy[0]
	c.CmNew0 = new(big.Int).SetBytes(inp.CmNew[0])
	for k := 0; k < 6; k++ {
		c.CNew0[k] = inp.CNew[0][k]
	}
	c.PkNew0 = inp.PkNew[0]
	c.RhoNew0 = inp.RhoNew[0]
	c.RandNew0 = inp.RandNew[0]

	c.R0 = new(big.Int).SetBytes(inp.R[0])
	c.G0 = sw_bls12377.NewG1Affine(inp.G[0])
	c.G_b0 = sw_bls12377.NewG1Affine(inp.G_b[0])
	c.G_r0 = sw_bls12377.NewG1Affine(inp.G_r[0])
	c.EncKey0 = sw_bls12377.NewG1Affine(inp.EncKey[0])

	// --- Remplissage pour le coin 1 ---
	c.OldCoin1 = inp.OldCoin[1]
	c.OldEnergy1 = inp.OldEnergy[1]
	c.CmOld1 = new(big.Int).SetBytes(inp.CmOld[1])
	c.SnOld1 = new(big.Int).SetBytes(inp.SnOld[1])
	c.PkOld1 = new(big.Int).SetBytes(inp.PkOld[1])
	c.SkOld1 = inp.SkOld[1]
	c.RhoOld1 = inp.RhoOld[1]
	c.RandOld1 = inp.RandOld[1]

	c.NewCoin1 = inp.NewCoin[1]
	c.NewEnergy1 = inp.NewEnergy[1]
	c.CmNew1 = new(big.Int).SetBytes(inp.CmNew[1])
	for k := 0; k < 6; k++ {
		c.CNew1[k] = inp.CNew[1][k]
	}
	c.PkNew1 = inp.PkNew[1]
	c.RhoNew1 = inp.RhoNew[1]
	c.RandNew1 = inp.RandNew[1]

	c.R1 = new(big.Int).SetBytes(inp.R[1])
	c.G1 = sw_bls12377.NewG1Affine(inp.G[1])
	c.G_b1 = sw_bls12377.NewG1Affine(inp.G_b[1])
	c.G_r1 = sw_bls12377.NewG1Affine(inp.G_r[1])
	c.EncKey1 = sw_bls12377.NewG1Affine(inp.EncKey[1])

	// --- Remplissage pour le coin 2 ---
	c.OldCoin2 = inp.OldCoin[2]
	c.OldEnergy2 = inp.OldEnergy[2]
	c.CmOld2 = new(big.Int).SetBytes(inp.CmOld[2])
	c.SnOld2 = new(big.Int).SetBytes(inp.SnOld[2])
	c.PkOld2 = new(big.Int).SetBytes(inp.PkOld[2])
	c.SkOld2 = inp.SkOld[2]
	c.RhoOld2 = inp.RhoOld[2]
	c.RandOld2 = inp.RandOld[2]

	c.NewCoin2 = inp.NewCoin[2]
	c.NewEnergy2 = inp.NewEnergy[2]
	c.CmNew2 = new(big.Int).SetBytes(inp.CmNew[2])
	for k := 0; k < 6; k++ {
		c.CNew2[k] = inp.CNew[2][k]
	}
	c.PkNew2 = inp.PkNew[2]
	c.RhoNew2 = inp.RhoNew[2]
	c.RandNew2 = inp.RandNew[2]

	c.R2 = new(big.Int).SetBytes(inp.R[2])
	c.G2 = sw_bls12377.NewG1Affine(inp.G[2])
	c.G_b2 = sw_bls12377.NewG1Affine(inp.G_b[2])
	c.G_r2 = sw_bls12377.NewG1Affine(inp.G_r[2])
	c.EncKey2 = sw_bls12377.NewG1Affine(inp.EncKey[2])

	return &c, nil
}

///////////

// CircuitTxF3 représente un circuit pour 3 coins.
type CircuitTxF3 struct {
	// ----- Coin 0 -----
	// Données de la note d'entrée (publiques)
	InCoin0   frontend.Variable `gnark:",public"`
	InEnergy0 frontend.Variable `gnark:",public"`
	InCm0     frontend.Variable `gnark:",public"`
	InSn0     frontend.Variable `gnark:",public"` // PRF_{sk}(rho)
	InPk0     frontend.Variable `gnark:",public"`
	InSk0     frontend.Variable `gnark:",public"`
	InRho0    frontend.Variable `gnark:",public"`
	InRand0   frontend.Variable `gnark:",public"`

	// Données de la note de sortie (publiques)
	OutCoin0   frontend.Variable `gnark:",public"`
	OutEnergy0 frontend.Variable `gnark:",public"`
	OutCm0     frontend.Variable `gnark:",public"`
	OutSn0     frontend.Variable `gnark:",public"`
	OutPk0     frontend.Variable `gnark:",public"`
	OutRho0    frontend.Variable `gnark:",public"`
	OutRand0   frontend.Variable `gnark:",public"`

	// Tableaux auxiliaires pour le coin 0 (issus de l'encryption)
	C0      [5]frontend.Variable
	DecVal0 [5]frontend.Variable

	// ----- Coin 1 -----
	// Données de la note d'entrée (publiques)
	InCoin1   frontend.Variable `gnark:",public"`
	InEnergy1 frontend.Variable `gnark:",public"`
	InCm1     frontend.Variable `gnark:",public"`
	InSn1     frontend.Variable `gnark:",public"` // PRF_{sk}(rho)
	InPk1     frontend.Variable `gnark:",public"`
	InSk1     frontend.Variable `gnark:",public"`
	InRho1    frontend.Variable `gnark:",public"`
	InRand1   frontend.Variable `gnark:",public"`

	// Données de la note de sortie (publiques)
	OutCoin1   frontend.Variable `gnark:",public"`
	OutEnergy1 frontend.Variable `gnark:",public"`
	OutCm1     frontend.Variable `gnark:",public"`
	OutSn1     frontend.Variable `gnark:",public"`
	OutPk1     frontend.Variable `gnark:",public"`
	OutRho1    frontend.Variable `gnark:",public"`
	OutRand1   frontend.Variable `gnark:",public"`

	// Tableaux auxiliaires pour le coin 1
	C1      [5]frontend.Variable
	DecVal1 [5]frontend.Variable

	// ----- Coin 2 -----
	// Données de la note d'entrée (publiques)
	InCoin2   frontend.Variable `gnark:",public"`
	InEnergy2 frontend.Variable `gnark:",public"`
	InCm2     frontend.Variable `gnark:",public"`
	InSn2     frontend.Variable `gnark:",public"` // PRF_{sk}(rho)
	InPk2     frontend.Variable `gnark:",public"`
	InSk2     frontend.Variable `gnark:",public"`
	InRho2    frontend.Variable `gnark:",public"`
	InRand2   frontend.Variable `gnark:",public"`

	// Données de la note de sortie (publiques)
	OutCoin2   frontend.Variable `gnark:",public"`
	OutEnergy2 frontend.Variable `gnark:",public"`
	OutCm2     frontend.Variable `gnark:",public"`
	OutSn2     frontend.Variable `gnark:",public"`
	OutPk2     frontend.Variable `gnark:",public"`
	OutRho2    frontend.Variable `gnark:",public"`
	OutRand2   frontend.Variable `gnark:",public"`

	// Tableaux auxiliaires pour le coin 2
	C2      [5]frontend.Variable
	DecVal2 [5]frontend.Variable

	// ----- Paramètres -----
	SkT0    sw_bls12377.G1Affine
	R0      frontend.Variable
	G0      sw_bls12377.G1Affine `gnark:",public"`
	G_b0    sw_bls12377.G1Affine `gnark:",public"`
	G_r0    sw_bls12377.G1Affine `gnark:",public"`
	EncKey0 sw_bls12377.G1Affine

	SkT1    sw_bls12377.G1Affine
	R1      frontend.Variable
	G1      sw_bls12377.G1Affine `gnark:",public"`
	G_b1    sw_bls12377.G1Affine `gnark:",public"`
	G_r1    sw_bls12377.G1Affine `gnark:",public"`
	EncKey1 sw_bls12377.G1Affine

	SkT2    sw_bls12377.G1Affine
	R2      frontend.Variable
	G2      sw_bls12377.G1Affine `gnark:",public"`
	G_b2    sw_bls12377.G1Affine `gnark:",public"`
	G_r2    sw_bls12377.G1Affine `gnark:",public"`
	EncKey2 sw_bls12377.G1Affine
}

// Define implémente les contraintes du circuit pour 3 coins.
func (c *CircuitTxF3) Define(api frontend.API) error {
	// --- Traitement du coin 0 ---
	decVal0 := DecZKReg(api, c.C0[:], c.SkT0)
	for i := 0; i < 5; i++ {
		api.AssertIsEqual(c.DecVal0[i], decVal0[i])
	}

	snComputed0 := PRF(api, c.InSk0, c.InRho0)
	api.AssertIsEqual(c.InSn0, snComputed0)

	api.AssertIsEqual(c.InCoin0, c.OutCoin0)
	api.AssertIsEqual(c.InEnergy0, c.OutEnergy0)

	hasher0, _ := mimc.NewMiMC(api)
	hasher0.Write(c.OutCoin0)
	hasher0.Write(c.OutEnergy0)
	hasher0.Write(c.OutRho0)
	hasher0.Write(c.OutRand0)
	cm0 := hasher0.Sum()
	api.AssertIsEqual(c.OutCm0, cm0)

	// --- Traitement du coin 1 ---
	decVal1 := DecZKReg(api, c.C1[:], c.SkT1)
	for i := 0; i < 5; i++ {
		api.AssertIsEqual(c.DecVal1[i], decVal1[i])
	}

	snComputed1 := PRF(api, c.InSk1, c.InRho1)
	api.AssertIsEqual(c.InSn1, snComputed1)

	api.AssertIsEqual(c.InCoin1, c.OutCoin1)
	api.AssertIsEqual(c.InEnergy1, c.OutEnergy1)

	hasher1, _ := mimc.NewMiMC(api)
	hasher1.Write(c.OutCoin1)
	hasher1.Write(c.OutEnergy1)
	hasher1.Write(c.OutRho1)
	hasher1.Write(c.OutRand1)
	cm1 := hasher1.Sum()
	api.AssertIsEqual(c.OutCm1, cm1)

	// --- Traitement du coin 2 ---
	decVal2 := DecZKReg(api, c.C2[:], c.SkT2)
	for i := 0; i < 5; i++ {
		api.AssertIsEqual(c.DecVal2[i], decVal2[i])
	}

	snComputed2 := PRF(api, c.InSk2, c.InRho2)
	api.AssertIsEqual(c.InSn2, snComputed2)

	api.AssertIsEqual(c.InCoin2, c.OutCoin2)
	api.AssertIsEqual(c.InEnergy2, c.OutEnergy2)

	hasher2, _ := mimc.NewMiMC(api)
	hasher2.Write(c.OutCoin2)
	hasher2.Write(c.OutEnergy2)
	hasher2.Write(c.OutRho2)
	hasher2.Write(c.OutRand2)
	cm2 := hasher2.Sum()
	api.AssertIsEqual(c.OutCm2, cm2)

	// --- Vérifications globales (encryption) ---
	// Pour le coin 0
	G_r_b0 := new(sw_bls12377.G1Affine)
	G_r_b0.ScalarMul(api, c.G_b0, c.R0)
	api.AssertIsEqual(c.EncKey0.X, G_r_b0.X)
	api.AssertIsEqual(c.EncKey0.Y, G_r_b0.Y)

	// Pour le coin 1
	G_r_b1 := new(sw_bls12377.G1Affine)
	G_r_b1.ScalarMul(api, c.G_b1, c.R1)
	api.AssertIsEqual(c.EncKey1.X, G_r_b1.X)
	api.AssertIsEqual(c.EncKey1.Y, G_r_b1.Y)

	// Pour le coin 2
	G_r_b2 := new(sw_bls12377.G1Affine)
	G_r_b2.ScalarMul(api, c.G_b2, c.R2)
	api.AssertIsEqual(c.EncKey2.X, G_r_b2.X)
	api.AssertIsEqual(c.EncKey2.Y, G_r_b2.Y)

	// Vérification de (G^R)==G_r pour chaque coin
	G_r0 := new(sw_bls12377.G1Affine)
	G_r0.ScalarMul(api, c.G0, c.R0)
	api.AssertIsEqual(c.G_r0.X, G_r0.X)
	api.AssertIsEqual(c.G_r0.Y, G_r0.Y)

	G_r1 := new(sw_bls12377.G1Affine)
	G_r1.ScalarMul(api, c.G1, c.R1)
	api.AssertIsEqual(c.G_r1.X, G_r1.X)
	api.AssertIsEqual(c.G_r1.Y, G_r1.Y)

	G_r2 := new(sw_bls12377.G1Affine)
	G_r2.ScalarMul(api, c.G2, c.R2)
	api.AssertIsEqual(c.G_r2.X, G_r2.X)
	api.AssertIsEqual(c.G_r2.Y, G_r2.Y)

	// Vérification de la dérivation de la clé publique pour chaque coin : InPk = MiMC(InSk)
	hasher0.Reset()
	hasher0.Write(c.InSk0)
	pk0 := hasher0.Sum()
	api.AssertIsEqual(c.InPk0, pk0)

	hasher1.Reset()
	hasher1.Write(c.InSk1)
	pk1 := hasher1.Sum()
	api.AssertIsEqual(c.InPk1, pk1)

	hasher2.Reset()
	hasher2.Write(c.InSk2)
	pk2 := hasher2.Sum()
	api.AssertIsEqual(c.InPk2, pk2)

	return nil
}

// BuildWitness construit le témoin pour le circuit avec 3 coins.
func (ip *InputTxFN) BuildWitness3() (frontend.Circuit, error) {
	// Vérifie que l'input contient exactement 3 coins.
	if len(ip.InCoin) != 3 {
		return nil, fmt.Errorf("InputTxFN.BuildWitness: expected exactly 3 coins, got %d", len(ip.InCoin))
	}

	var c CircuitTxF3

	// ----- Attribution pour le coin 0 -----
	c.InCoin0 = ip.InCoin[0]
	c.InEnergy0 = ip.InEnergy[0]
	c.InCm0 = ip.InCm[0]
	c.InSn0 = ip.InSn[0]
	c.InPk0 = ip.InPk[0]
	c.InSk0 = ip.InSk[0]
	c.InRho0 = ip.InRho[0]
	c.InRand0 = ip.InRand[0]

	c.OutCoin0 = ip.OutCoin[0]
	c.OutEnergy0 = ip.OutEnergy[0]
	c.OutCm0 = ip.OutCm[0]
	c.OutSn0 = ip.OutSn[0]
	c.OutPk0 = ip.OutPk[0]
	c.OutRho0 = ip.OutRho[0]
	c.OutRand0 = ip.OutRand[0]

	if len(ip.C) < 3 || len(ip.DecVal) < 3 {
		return nil, fmt.Errorf("InputTxFN.BuildWitness: encryption arrays for 3 coins are required")
	}
	for i := 0; i < 5; i++ {
		c.C0[i] = ip.C[0][i]
		c.DecVal0[i] = ip.DecVal[0][i]
	}

	// ----- Attribution pour le coin 1 -----
	c.InCoin1 = ip.InCoin[1]
	c.InEnergy1 = ip.InEnergy[1]
	c.InCm1 = ip.InCm[1]
	c.InSn1 = ip.InSn[1]
	c.InPk1 = ip.InPk[1]
	c.InSk1 = ip.InSk[1]
	c.InRho1 = ip.InRho[1]
	c.InRand1 = ip.InRand[1]

	c.OutCoin1 = ip.OutCoin[1]
	c.OutEnergy1 = ip.OutEnergy[1]
	c.OutCm1 = ip.OutCm[1]
	c.OutSn1 = ip.OutSn[1]
	c.OutPk1 = ip.OutPk[1]
	c.OutRho1 = ip.OutRho[1]
	c.OutRand1 = ip.OutRand[1]

	for i := 0; i < 5; i++ {
		c.C1[i] = ip.C[1][i]
		c.DecVal1[i] = ip.DecVal[1][i]
	}

	// ----- Attribution pour le coin 2 -----
	c.InCoin2 = ip.InCoin[2]
	c.InEnergy2 = ip.InEnergy[2]
	c.InCm2 = ip.InCm[2]
	c.InSn2 = ip.InSn[2]
	c.InPk2 = ip.InPk[2]
	c.InSk2 = ip.InSk[2]
	c.InRho2 = ip.InRho[2]
	c.InRand2 = ip.InRand[2]

	c.OutCoin2 = ip.OutCoin[2]
	c.OutEnergy2 = ip.OutEnergy[2]
	c.OutCm2 = ip.OutCm[2]
	c.OutSn2 = ip.OutSn[2]
	c.OutPk2 = ip.OutPk[2]
	c.OutRho2 = ip.OutRho[2]
	c.OutRand2 = ip.OutRand[2]

	for i := 0; i < 5; i++ {
		c.C2[i] = ip.C[2][i]
		c.DecVal2[i] = ip.DecVal[2][i]
	}

	// ----- Paramètres -----
	c.SkT0 = sw_bls12377.NewG1Affine(ip.SkT[0])
	c.SkT1 = sw_bls12377.NewG1Affine(ip.SkT[1])
	c.SkT2 = sw_bls12377.NewG1Affine(ip.SkT[2])
	c.EncKey0 = sw_bls12377.NewG1Affine(ip.EncKey[0])
	c.EncKey1 = sw_bls12377.NewG1Affine(ip.EncKey[1])
	c.EncKey2 = sw_bls12377.NewG1Affine(ip.EncKey[2])
	c.R0 = ip.R[0]
	c.R1 = ip.R[1]
	c.R2 = ip.R[2]
	c.G0 = sw_bls12377.NewG1Affine(ip.G[0])
	c.G1 = sw_bls12377.NewG1Affine(ip.G[1])
	c.G2 = sw_bls12377.NewG1Affine(ip.G[2])
	c.G_b0 = sw_bls12377.NewG1Affine(ip.G_b[0])
	c.G_b1 = sw_bls12377.NewG1Affine(ip.G_b[1])
	c.G_b2 = sw_bls12377.NewG1Affine(ip.G_b[2])
	c.G_r0 = sw_bls12377.NewG1Affine(ip.G_r[0])
	c.G_r1 = sw_bls12377.NewG1Affine(ip.G_r[1])
	c.G_r2 = sw_bls12377.NewG1Affine(ip.G_r[2])

	return &c, nil
}

/////////////

// CircuitWithdraw formalise l’algo 4 (Withdraw).
// Il faut prouver :
// 1) snIn = PRF(skIn, rhoIn)
// 2) cmOut = Com(Γout || pkOut || rhoOut, rOut)
// 3) cipherAux = Enc(pkT, b, skIn, pkOut)   (avec la bonne aléa)
type CircuitWithdraw struct {
	// ----- Variables PUBLIQUES -----
	SnIn  frontend.Variable    `gnark:",public"` // snᵢ^(in)
	CmOut frontend.Variable    `gnark:",public"` // cmᵢ^(out)
	PkT   sw_bls12377.G1Affine `gnark:",public"` // pkₜ
	// CipherAux correspond au ciphertext (bᵢ, skᵢ^(in), pkᵢ^(out)) chiffré sous pkₜ
	// Selon votre schéma, ça peut être 4, 5, 6 field elements, etc.
	// Ici on suppose 5 elements par ex.
	CipherAux [3]frontend.Variable `gnark:",public"`

	// ----- Variables PRIVEES (witness) -----
	SkIn frontend.Variable // skᵢ^(in)
	B    frontend.Variable // bᵢ
	//REnc frontend.Variable // rEnc (aléa d’encryption)

	// Note consommée (in)
	NIn struct {
		Coins  frontend.Variable // ou int64 si vous avez un seul champ
		Energy frontend.Variable // si vous gérez 2 goods
		PkIn   frontend.Variable
		RhoIn  frontend.Variable
		RIn    frontend.Variable
		CmIn   frontend.Variable
	}

	// Note de sortie (out)
	NOut struct {
		Coins  frontend.Variable
		Energy frontend.Variable
		PkOut  frontend.Variable
		RhoOut frontend.Variable
		ROut   frontend.Variable
		CmOut  frontend.Variable
	}
}

// Define impose les contraintes ZK pour le Withdraw.
func (c *CircuitWithdraw) Define(api frontend.API) error {

	// (1) Vérifier snIn = PRF(skIn, rhoIn)
	//     => On recalcule snIn via votre PRF
	snComputed := PRF(api, c.SkIn, c.NIn.RhoIn)
	api.AssertIsEqual(c.SnIn, snComputed)

	// (2) Vérifier cmOut = Com(Γout, pkOut, rhoOut, rOut)
	//     => On recalcule le commit via MiMC ou autre
	hasher, _ := mimc.NewMiMC(api)
	hasher.Write(c.NOut.Coins)
	hasher.Write(c.NOut.Energy)
	//hasher.Write(c.NOut.PkOut)
	hasher.Write(c.NOut.RhoOut)
	// rOut peut être un champ de "commitment random"
	// ou alors vous l’incluez différemment selon votre scheme
	hasher.Write(c.NOut.ROut)
	cmComputed := hasher.Sum()
	api.AssertIsEqual(c.CmOut, cmComputed)
	// On s’assure aussi que la note de sortie a un cmOut cohérent :
	//api.AssertIsEqual(c.NOut.CmOut, cmComputed)

	// (3) Vérifier que CipherAux = Enc(pkT, (b, skIn, pkOut)) avec rEnc
	//     => On refait la logique "encryption" en circuit
	//        puis on compare
	encVal := EncWithdrawMimc(api, c.NOut.PkOut, c.SkIn, c.B, c.PkT)
	// Compare chaque champ
	for i := 0; i < 3; i++ {
		api.AssertIsEqual(c.CipherAux[i], encVal[i])
	}
	return nil
}

// func EncZKWithdraw(api frontend.API,
// 	b, skIn, pkOut frontend.Variable,
// 	pkT sw_bls12377.G1Affine,
// ) [5]frontend.Variable {

// 	// EXEMPLE : on concatène pkT.X, pkT.Y, rEnc,
// 	//           on fait un hashing en plusieurs étapes,
// 	//           et on l’utilise comme masque.
// 	// Adaptez selon votre schéma d’encryption.
// 	h, _ := mimc.NewMiMC(api)
// 	// on “mixe” la clé publique pkT et rEnc
// 	h.Write(pkT.X)
// 	h.Write(pkT.Y)
// 	//h.Write(rEnc)
// 	mask1 := h.Sum()
// 	h.Write(mask1)
// 	mask2 := h.Sum()
// 	h.Write(mask2)
// 	mask3 := h.Sum()
// 	h.Write(mask3)
// 	mask4 := h.Sum()
// 	h.Write(mask4)
// 	mask5 := h.Sum()

// 	// “Chiffrement” = x + mask
// 	cB := api.Add(b, mask1)
// 	cSkIn := api.Add(skIn, mask2)
// 	cPkOut := api.Add(pkOut, mask3)

// 	// Vous pouvez rajouter 2 champs pour la démo, ex : “dummy1” + “dummy2”
// 	dummy1 := mask4
// 	dummy2 := mask5

// 	return [5]frontend.Variable{cB, cSkIn, cPkOut, dummy1, dummy2}
// }

// BuildEncWithdrawMimc réalise (hors-circuit) le "chiffrement" de 3 valeurs
// (b, skIn, pkOut) avec la clé publique EncKey et l'aléa rEnc, suivant
// la même stratégie que BuildEncRegMimc (répétitions h.Write(...) + h.Sum(...)).
// func BuildEncWithdrawMimc_(
// 	EncKey bls12377.G1Affine,
// 	b, skIn, pkOut []byte,
// ) [3]bls12377_fp.Element {

// 	// 1) on crée un hasher MiMC sur BW6-761
// 	h := mimc_bw6_761.NewMiMC()

// 	// 2) on convertit EncKey.X, EncKey.Y en []byte
// 	encKeyX := EncKey.X.Bytes()
// 	encKeyY := EncKey.Y.Bytes()

// 	// 3) On "mixe" pkEncKeyX, pkEncKeyY et rEnc
// 	h.Write(encKeyX[:])
// 	h.Write(encKeyY[:])
// 	//h.Write(rEnc)

// 	// 4) On calcule 3 valeurs de hash successives (hEnc1, hEnc2, hEnc3)
// 	var hEnc1, hEnc2, hEnc3 []byte

// 	// hEnc1 = h.Sum()
// 	hEnc1 = h.Sum(nil)

// 	// hEnc2 = H( hEnc1 )
// 	h.Write(hEnc1)
// 	hEnc2 = h.Sum(nil)

// 	// hEnc3 = H( hEnc2 )
// 	h.Write(hEnc2)
// 	hEnc3 = h.Sum(nil)

// 	// 5) on convertit b, skIn, pkOut en big.Int puis en fp.Element
// 	bInt := new(big.Int).SetBytes(b)
// 	skInInt := new(big.Int).SetBytes(skIn)
// 	pkOutInt := new(big.Int).SetBytes(pkOut)

// 	var bEl, skInEl, pkOutEl bls12377_fp.Element
// 	bEl.SetBigInt(bInt)
// 	skInEl.SetBigInt(skInInt)
// 	pkOutEl.SetBigInt(pkOutInt)

// 	// 6) on convertit hEnc1, hEnc2, hEnc3 en fp.Element
// 	var m1, m2, m3 bls12377_fp.Element
// 	m1.SetBigInt(new(big.Int).SetBytes(hEnc1))
// 	m2.SetBigInt(new(big.Int).SetBytes(hEnc2))
// 	m3.SetBigInt(new(big.Int).SetBytes(hEnc3))

// 	// 7) chiffrement additif = clair + masque
// 	bEnc := new(bls12377_fp.Element).Add(&bEl, &m1)
// 	skInEnc := new(bls12377_fp.Element).Add(&skInEl, &m2)
// 	pkOutEnc := new(bls12377_fp.Element).Add(&pkOutEl, &m3)

// 	// 8) on retourne le tableau [3] d'éléments
// 	return [3]bls12377_fp.Element{*bEnc, *skInEnc, *pkOutEnc}
// }

// // Structure d'input pour F multi‑coin (version FN)
// type InputTxFN struct {
// 	// Champs coin‑spécifiques (pour chaque coin)
// 	InCoin   []frontend.Variable
// 	InEnergy []frontend.Variable
// 	InCm     []frontend.Variable
// 	InSn     []frontend.Variable
// 	InPk     []frontend.Variable
// 	InSk     []frontend.Variable
// 	InRho    []frontend.Variable
// 	InRand   []frontend.Variable

// 	OutCoin   []frontend.Variable
// 	OutEnergy []frontend.Variable
// 	OutCm     []frontend.Variable
// 	OutSn     []frontend.Variable
// 	OutPk     []frontend.Variable
// 	OutRho    []frontend.Variable
// 	OutRand   []frontend.Variable

// 	// Paramètre global commun
// 	SkT []bls12377.G1Affine

// 	// Éventuellement, d'autres champs coin‑spécifiques (si nécessaire)
// 	// Par exemple, si vous souhaitez avoir un SnIn et CmOut par coin :
// 	SnIn  []frontend.Variable
// 	CmOut []frontend.Variable

// 	// Pour chaque coin, un tableau de 5 éléments (ex. issus de l'encryption)
// 	C      [][5][]byte
// 	DecVal [][5][]byte

// 	// Paramètres globaux (communs à tous les coins)
// 	EncKey []bls12377.G1Affine
// 	// Si R doit être coin‑spécifique, on pourra en faire une slice, sinon global :
// 	R   []frontend.Variable
// 	G   []bls12377.G1Affine
// 	G_b []bls12377.G1Affine
// 	G_r []bls12377.G1Affine
// }

type InputTxDraw struct {
	SnIn      []byte
	CmOut     []byte
	PkT       bls12377.G1Affine
	CipherAux [3][]byte
	SkIn      []byte
	B         []byte
	REnc      []byte
	NInCoins  []byte // ou int64 si vous avez un seul champ
	NInEnergy []byte // si vous gérez 2 goods
	NInPkIn   []byte
	NInRhoIn  []byte
	NInRIn    []byte
	NInCmIn   []byte

	NOutCoins  []byte
	NOutEnergy []byte
	NOutPkOut  []byte
	NOutRhoOut []byte
	NOutROut   []byte
	NOutCmOut  []byte
}

func (ip *InputTxDraw) BuildWitness() (frontend.Circuit, error) {

	var c CircuitWithdraw // CircuitTxF2 est défini avec des tableaux statiques pour 2 coins.

	c.SnIn = new(big.Int).SetBytes(ip.SnIn)
	c.CmOut = new(big.Int).SetBytes(ip.CmOut)
	c.PkT = sw_bls12377.NewG1Affine(ip.PkT)
	for i := 0; i < 3; i++ {
		c.CipherAux[i] = new(big.Int).SetBytes(ip.CipherAux[i])
	}
	c.SkIn = new(big.Int).SetBytes(ip.SkIn)
	c.B = new(big.Int).SetBytes(ip.B)
	//c.REnc = new(big.Int).SetBytes(ip.REnc)

	c.NIn.Coins = new(big.Int).SetBytes(ip.NInCoins)
	c.NIn.Energy = new(big.Int).SetBytes(ip.NInEnergy)
	c.NIn.PkIn = new(big.Int).SetBytes(ip.NInPkIn)
	c.NIn.RhoIn = new(big.Int).SetBytes(ip.NInRhoIn)
	c.NIn.RIn = new(big.Int).SetBytes(ip.NInRIn)
	c.NIn.CmIn = new(big.Int).SetBytes(ip.NInCmIn)

	c.NOut.Coins = new(big.Int).SetBytes(ip.NOutCoins)
	c.NOut.Energy = new(big.Int).SetBytes(ip.NOutEnergy)
	c.NOut.PkOut = new(big.Int).SetBytes(ip.NOutPkOut)
	c.NOut.RhoOut = new(big.Int).SetBytes(ip.NOutRhoOut)
	c.NOut.ROut = new(big.Int).SetBytes(ip.NOutROut)
	c.NOut.CmOut = new(big.Int).SetBytes(ip.NOutCmOut)
	return &c, nil
}

func BuildEncWithdrawMimc(pkOut, skIn, bid []byte, EncKey bls12377.G1Affine) [3]bls12377_fp.Element {

	pk_out := new(big.Int).SetBytes(pkOut[:])
	sk_in := new(big.Int).SetBytes(skIn[:])
	bid_ := new(big.Int).SetBytes(bid[:])

	h := mimc_bw6_761.NewMiMC()

	EncKeyX := EncKey.X.Bytes()
	EncKeyXBytes := make([]byte, len(EncKeyX))
	copy(EncKeyXBytes[:], EncKeyX[:])

	EncKeyY := EncKey.Y.Bytes()
	EncKeyYBytes := make([]byte, len(EncKeyY))
	copy(EncKeyYBytes[:], EncKeyY[:])

	//compute H(enc_key)
	h.Write(EncKeyXBytes)
	h.Write(EncKeyYBytes)
	var h_enc_key []byte
	h_enc_key = h.Sum(h_enc_key)

	//compute H(H(enc_key))
	var h_h_enc_key []byte
	h.Write(h_enc_key)
	h_h_enc_key = h.Sum(h_h_enc_key)

	//compute H(H(H(enc_key)))
	var h_h_h_enc_key []byte
	h.Write(h_h_enc_key)
	h_h_h_enc_key = h.Sum(h_h_h_enc_key)

	//compute H(H(H(H(enc_key))))
	var h_h_h_h_enc_key []byte
	h.Write(h_h_h_enc_key)
	h_h_h_h_enc_key = h.Sum(h_h_h_h_enc_key)

	//compute H(H(H(H(H(enc_key)))))
	var h_h_h_h_h_enc_key []byte
	h.Write(h_h_h_h_enc_key)
	h_h_h_h_h_enc_key = h.Sum(h_h_h_h_h_enc_key)

	//compute H(H(H(H(H(H(enc_key))))))
	var h_h_h_h_h_h_enc_key []byte
	h.Write(h_h_h_h_h_enc_key)
	h_h_h_h_h_h_enc_key = h.Sum(h_h_h_h_h_h_enc_key)

	//encrypt pk
	pk_ := new(bls12377_fp.Element).SetBigInt(pk_out)
	pk_enc := new(bls12377_fp.Element).Add(pk_, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_enc_key[:])))

	//encrypt coins
	skin := new(bls12377_fp.Element).SetBigInt(sk_in)
	skin_enc := new(bls12377_fp.Element).Add(skin, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_enc_key[:])))

	//encrypt energy
	bid__ := new(bls12377_fp.Element).SetBigInt(bid_)
	bid_enc := new(bls12377_fp.Element).Add(bid__, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_h_enc_key[:])))

	// //encrypt rho
	// rho_ := new(bls12377_fp.Element).SetBigInt(rho)
	// rho_enc := new(bls12377_fp.Element).Add(rho_, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_h_h_enc_key[:])))

	// //encrypt rand
	// rand_ := new(bls12377_fp.Element).SetBigInt(rand)
	// rand_enc := new(bls12377_fp.Element).Add(rand_, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_h_h_h_enc_key[:])))

	// //encrypt cm
	// cm_ := new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(cm[:]))
	// cm_enc := new(bls12377_fp.Element).Add(cm_, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_h_h_h_h_enc_key[:])))

	return [3]bls12377_fp.Element{*pk_enc, *skin_enc, *bid_enc} //, *rho_enc, *rand_enc, *cm_enc}
}

func EncWithdrawMimc(api frontend.API, pkOut, skIn, bid frontend.Variable, enc_key sw_bls12377.G1Affine) []frontend.Variable {
	h, _ := mimc.NewMiMC(api)

	//compute H(enc_key)
	h.Write(enc_key.X)
	h.Write(enc_key.Y)
	h_enc_key := h.Sum()

	//compute H(H(enc_key))
	h.Write(h.Sum())
	h_h_enc_key := h.Sum()

	//compute H(H(H(enc_key)))
	h.Write(h_h_enc_key)
	h_h_h_enc_key := h.Sum()

	// //compute H(H(H(H(enc_key))))
	// h.Write(h_h_h_enc_key)
	// h_h_h_h_enc_key := h.Sum()

	// //compute H(H(H(H(H(enc_key)))))
	// h.Write(h_h_h_h_enc_key)
	// h_h_h_h_h_enc_key := h.Sum()

	// //compute H(H(H(H(H(H(enc_key))))))
	// h.Write(h_h_h_h_h_enc_key)
	// h_h_h_h_h_h_enc_key := h.Sum()

	//encrypt pkOut
	pk_enc := api.Add(pkOut, h_enc_key)

	//encrypt skIn
	sk_enc := api.Add(skIn, h_h_enc_key)

	//encrypt bid
	bid_enc := api.Add(bid, h_h_h_enc_key)

	// //encrypt gammaIn
	// gamma_enc := api.Add(gammaInCoins, h_h_h_h_enc_key)

	// //encrypt energy
	// energy_enc := api.Add(gammaInEnergy, h_h_h_h_h_enc_key)

	//return encrypted values
	return []frontend.Variable{pk_enc, sk_enc, bid_enc} //, gamma_enc, energy_enc}
}

/////////////

// type CircuitTxDraw struct {
// 	// old note data (PUBLIC)
// 	OldCoin   frontend.Variable `gnark:",public"`
// 	OldEnergy frontend.Variable `gnark:",public"`
// 	CmOld     frontend.Variable `gnark:",public"`
// 	SnOld     frontend.Variable `gnark:",public"` // PRF_{sk}(rho)
// 	PkOld     frontend.Variable `gnark:",public"`

// 	// new note data (PUBLIC)
// 	NewCoin   frontend.Variable    `gnark:",public"`
// 	NewEnergy frontend.Variable    `gnark:",public"`
// 	CmNew     frontend.Variable    `gnark:",public"`
// 	CNew      [6]frontend.Variable `gnark:",public"` // "cipher" simulé

// 	// old note data (PRIVATE)
// 	SkOld   frontend.Variable
// 	RhoOld  frontend.Variable
// 	RandOld frontend.Variable

// 	// new note data (PRIVATE)
// 	PkNew   frontend.Variable
// 	RhoNew  frontend.Variable
// 	RandNew frontend.Variable

// 	////

// 	R frontend.Variable
// 	//B      frontend.Variable
// 	G      sw_bls12377.G1Affine `gnark:",public"`
// 	G_b    sw_bls12377.G1Affine `gnark:",public"`
// 	G_r    sw_bls12377.G1Affine `gnark:",public"`
// 	EncKey sw_bls12377.G1Affine

// 	////
// }

// func (c *CircuitTxDraw) Define(api frontend.API) error {
// 	// 1) Recalcule cmOld[i]
// 	hasher, _ := mimc.NewMiMC(api)
// 	hasher.Reset()
// 	hasher.Write(c.OldCoin)
// 	hasher.Write(c.OldEnergy)
// 	hasher.Write(c.RhoOld)
// 	hasher.Write(c.RandOld)
// 	cm := hasher.Sum()
// 	api.AssertIsEqual(c.CmOld, cm)
// 	// 2) Recalcule snOld[i] = MiMC(sk, rho) (façon PRF)
// 	snComputed := PRF(api, c.SkOld, c.RhoOld)
// 	api.AssertIsEqual(c.SnOld, snComputed)
// 	// 3) Recalcule cmNew[j]
// 	hasher.Reset()
// 	hasher.Write(c.NewCoin)
// 	hasher.Write(c.NewEnergy)
// 	hasher.Write(c.RhoNew)
// 	hasher.Write(c.RandNew)
// 	cm = hasher.Sum()
// 	api.AssertIsEqual(c.CmNew, cm)
// 	// 4) Recalcule cNew[j] = MiMC(pk, coins, energy, rho, rand, cm)
// 	encVal := EncZK(api, c.PkNew,
// 		c.NewCoin, c.NewEnergy,
// 		c.RhoNew, c.RandNew, c.CmNew, c.EncKey)
// 	api.AssertIsEqual(c.CNew[0], encVal[0])
// 	api.AssertIsEqual(c.CNew[1], encVal[1])
// 	api.AssertIsEqual(c.CNew[2], encVal[2])
// 	api.AssertIsEqual(c.CNew[3], encVal[3])
// 	api.AssertIsEqual(c.CNew[4], encVal[4])
// 	api.AssertIsEqual(c.CNew[5], encVal[5])
// 	// 5) Vérifie conservation
// 	oldCoinsSum := api.Add(c.OldCoin, c.OldCoin)
// 	newCoinsSum := api.Add(c.NewCoin, c.NewCoin)
// 	api.AssertIsEqual(oldCoinsSum, newCoinsSum)

// 	oldEnergySum := api.Add(c.OldEnergy, c.OldEnergy)
// 	newEnergySum := api.Add(c.NewEnergy, c.NewEnergy)
// 	api.AssertIsEqual(oldEnergySum, newEnergySum)

// 	// EXTRA: Encryption check

// 	//(G^r)^b == EncKey
// 	G_r_b := new(sw_bls12377.G1Affine)
// 	G_r_b.ScalarMul(api, c.G_b, c.R)
// 	api.AssertIsEqual(c.EncKey.X, G_r_b.X)
// 	api.AssertIsEqual(c.EncKey.Y, G_r_b.Y)

// 	//(G^r) == G_r
// 	G_r := new(sw_bls12377.G1Affine)
// 	G_r.ScalarMul(api, c.G, c.R)
// 	api.AssertIsEqual(c.G_r.X, G_r.X)
// 	api.AssertIsEqual(c.G_r.Y, G_r.Y)

// 	//check a_pk = MiMC(a_sk)
// 	hasher.Reset()
// 	hasher.Write(c.SkOld)
// 	pk := hasher.Sum()
// 	api.AssertIsEqual(c.PkOld, pk)
// 	return nil
// }
