package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"log"
	"math/big"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

const subsidy = 10 // BTC

type Transaction struct {
	ID   []byte
	Vin  []TXInput
	Vout []TXOutput
}

///wallet. 해시키
func HashPubKey(pubKey []byte) []byte {
	publicSHA256 := sha256.Sum256(pubKey)

	RIPEMD160Hasher := ripemd160.New()
	_, err := RIPEMD160Hasher.Write(publicSHA256[:])
	if err != nil {
		log.Panic(err)
	}

	return RIPEMD160Hasher.Sum(nil)

}

///////// input.

type TXInput struct {
	Txid      []byte
	Vout      int
	Signature []byte
	PubKey    []byte
}

func (in *TXInput) UsesKey(pubKeyHash []byte) bool {
	lockingHash := HashPubKey(in.PubKey)
	return bytes.Compare(pubKeyHash, lockingHash) == 0
}

//////////// output.

type TXOutput struct {
	Value      uint64
	PubKeyHash []byte
}

func NewTXOutput(value uint64, address string) *TXOutput {
	txo := &TXOutput{value, nil}
	txo.Lock(address)

	return txo
}

func (out *TXOutput) Lock(address string) {
	pubKeyHash, _, err := base58.CheckDecode(address)
	if err != nil {
		log.Panic(err)
	}
	out.PubKeyHash = pubKeyHash
}

////////////

func NewTransaction(vin []TXInput, vout []TXOutput) *Transaction {
	tx := Transaction{nil, vin, vout}
	tx.SetID()

	return &tx
}

func (tx *Transaction) SetID() {
	buf := new(bytes.Buffer)

	encoder := gob.NewEncoder(buf)
	err := encoder.Encode(tx)
	if err != nil {
		log.Panic(err)
	}

	hash := sha256.Sum256(buf.Bytes())
	tx.ID = hash[:]
}

func NewCoinbaseTX(data, to string) *Transaction {
	txin := TXInput{[]byte{}, -1, nil, []byte(data)}
	txout := NewTXOutput(subsidy, to)

	return NewTransaction([]TXInput{txin}, []TXOutput{*txout})
}

func (tx *Transaction) IsCoinbase() bool {
	return bytes.Compare(tx.Vin[0].Txid, []byte{}) == 0 && tx.Vin[0].Vout == -1 && len(tx.Vin) == 1
}

func (tx *Transaction) Sign(privKey *ecdsa.PrivateKey, prevTXs map[string]*Transaction) {
	if tx.IsCoinbase() {
		return
	}

	// 거래의 복사본 생성
	txCopy := tx.TrimmedCopy()

	for inID, in := range txCopy.Vin {
		// 서명 대상 데이터 구성 및 초기화
		txCopy.Vin[inID].Signature = nil
		// 송신자 식별을 위해 이전 트랜잭션의 공개키를 넣음
		txCopy.Vin[inID].PubKey = prevTXs[hex.EncodeToString(in.Txid)].Vout[in.Vout].PubKeyHash
		txCopy.SetID()                // 거래를 해싱
		txCopy.Vin[inID].PubKey = nil // ID를 할당함

		// ecdsa.Sign으로 서명을 생성함
		r, s, err := ecdsa.Sign(rand.Reader, privKey, txCopy.ID)
		if err != nil {
			log.Panic(err)
		}
		// 타원곡선 암호화의 결과로 R,S가 생성되는데 연결해주면 된다.
		tx.Vin[inID].Signature = append(r.Bytes(), s.Bytes()...)
	}
}

// 대상 트랜잭션의 복사본 생성 함수
func (tx *Transaction) TrimmedCopy() *Transaction {
	var inputs []TXInput
	var outputs []TXOutput

	for _, in := range tx.Vin {
		inputs = append(inputs, TXInput{in.Txid, in.Vout, nil, nil})
	}
	for _, out := range tx.Vout {
		outputs = append(outputs, TXOutput{out.Value, out.PubKeyHash})
	}

	return &Transaction{nil, inputs, outputs}
}

// 서명 검증 함수
// 서명을 검증하기 위해 필요한것 - 해시된 데이터, 서명(R,S), 공개키(X,Y)
// parm으로 이전 트랜잭션을 받아옴 - 검증을 위해서 서명에 사용된 데이터를 해시해서 비교하기위함
func (tx *Transaction) Verify(prevTXs map[string]*Transaction) bool {
	txCopy := tx.TrimmedCopy()
	curve := elliptic.P256()

	for inID, in := range tx.Vin {
		// 서명에 사용할 데이터를 생성하고 해싱
		// 생성된 해시는 검증을 위해 만든것
		txCopy.Vin[inID].Signature = nil
		txCopy.Vin[inID].PubKey = prevTXs[hex.EncodeToString(in.Txid)].Vout[in.Vout].PubKeyHash
		txCopy.SetID()
		txCopy.Vin[inID].PubKey = nil

		// 서명 R,S 값 얻기
		var r, s big.Int

		sigLen := len(in.Signature)
		r.SetBytes(in.Signature[:sigLen/2])
		s.SetBytes(in.Signature[sigLen/2:])

		// 공개키 X,Y 값 얻기
		var x, y big.Int

		keyLen := len(in.PubKey)
		x.SetBytes(in.PubKey[:keyLen/2])
		y.SetBytes(in.PubKey[keyLen/2:])

		// 공개키 생성
		pubKey := ecdsa.PublicKey{curve, &x, &y}

		// 검증
		if isVerified := ecdsa.Verify(&pubKey, txCopy.ID, &r, &s); !isVerified {
			return false
		}
	}

	return true
}

func main() {

	println()

}
