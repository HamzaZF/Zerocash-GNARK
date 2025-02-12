package zerocash_gnark

import (
	"bytes"
	"fmt"
	"math/big"
	"os"
	"time"

	mimc_bw6_761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
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

// randBigInt renvoie un *big.Int pseudo-aléatoire (pour la démo).
func randBigInt() *big.Int {
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

// calcSerialMimc : calcule sn = MiMC(sk, rho) hors-circuit, pour être cohérent
// avec la PRF en circuit.
func calcSerialMimc(sk, rho []byte) []byte {
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

func buildEncMimc(EncKey bls12377.G1Affine, pk []byte, coins, energy, rho, rand *big.Int, cm []byte) []bls12377_fp.Element {

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

	return []bls12377_fp.Element{*pk_enc, *coins_enc, *energy_enc, *rho_enc, *rand_enc, *cm_enc}
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

//func buildEncMimc(pk []byte, coins, energy, rho, rand *big.Int, cm []byte) []byte {

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

// -----------------------------------------------------------------------------
// (4) InputProver + BuildWitness
// -----------------------------------------------------------------------------

type InputProver struct {
	// PUBLIC
	OldCoins  [2]*big.Int
	OldEnergy [2]*big.Int
	CmOld     [2][]byte
	SnOld     [2][]byte

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

		c.SkOld[i] = inp.SkOld[i]
		c.RhoOld[i] = inp.RhoOld[i]
		c.RandOld[i] = inp.RandOld[i]
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
		sn := calcSerialMimc(inp.OldSk[i], inp.OldNotes[i].Rho)
		snOld[i] = sn
	}
	// 2) generer (rhoNew, randNew), cmNew, cNew
	var rhoNew [2]*big.Int
	var randNew [2]*big.Int
	var cmNew [2][]byte
	//var cNew [2][][]byte
	var cNew [2]Note

	for j := 0; j < 2; j++ {
		rhoNew[j] = randBigInt()
		randNew[j] = randBigInt()
		cm := Committment(inp.NewVals[j].Coins, inp.NewVals[j].Energy,
			rhoNew[j], randNew[j])
		cmNew[j] = cm
		encVal := buildEncMimc(inp.EncKey, inp.NewPk[j],
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
) bool {

	var ip InputProver
	// old
	for i := 0; i < 2; i++ {
		ip.OldCoins[i] = old[i].Value.Coins
		ip.OldEnergy[i] = old[i].Value.Energy
		ip.CmOld[i] = old[i].Cm
		ip.SnOld[i] = tx.SnOld[i]

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
	err = groth16.Verify(p, globalVK, pubOnly)
	if err != nil {
		fmt.Println("Verify fail =>", err)
		return false
	}
	return true
}

// -----------------------------------------------------------------------------
// (6) loadOrGenerateKeys : PK, VK synchronisés
// -----------------------------------------------------------------------------

var (
	globalCCS constraint.ConstraintSystem
	globalPK  groth16.ProvingKey
	globalVK  groth16.VerifyingKey
)

func LoadOrGenerateKeys(circuit_type string) {

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
			fmt.Println("Circuit loaded from", cssFile)
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

			log.Info().Str("vkFile", vkFile).Str("pkFile", pkFile).Msg("Loading keys from disk")
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
			log.Info().Str("vkFile", vkFile).Str("pkFile", pkFile).Msg("Generating keys")
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

}

func fileExists(fname string) bool {
	if _, err := os.Stat(fname); err == nil {
		return true
	}
	return false
}
