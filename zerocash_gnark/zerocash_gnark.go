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
	}

	return globalCCS, globalPK, globalVK
}

func fileExists(fname string) bool {
	if _, err := os.Stat(fname); err == nil {
		return true
	}
	return false
}
