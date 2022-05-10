package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"log"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

// ECDSA = 타원곡선암호화
// 개인키에서 공개키를 만들때 & 디지털 서명을 만들때 사용된다.
// 공개키는 개인키로부터 도출된다.
// 개인키(k)* 타원곡선 생성포인트(G) = 공개키(K)
// 생성포인트는 x,y좌표가 주어지고 두개를 이어주면 공개키를 얻을 수 있다.
type Wallet struct { // 지갑은 단순히 개인키와 공개키를 가지고있다.
	privKey *ecdsa.PrivateKey
	pubKey  []byte
}

// 개인키를 생성하고 공개키를 생성후 지갑을 지정한다.

// 지갑을 생성하는 함수
func NewWallet() *Wallet {
	curve := elliptic.P256()
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	// rand == crypto/rand
	if err != nil {
		log.Panic(err)
	}
	pubKey := append(privKey.X.Bytes(), privKey.Y.Bytes()...)
	return &Wallet{privKey, pubKey}
}

// 지갑에서 공개키와 개인키 쌍을 설정한후, 주소를 생성할 수 있다.
// 주소는 개인키로부터 도출된다.

// 주소 생성 함수
func (w *Wallet) GetAddress() string {
	publicRIPEMD160 := HashPubKey(w.pubKey)
	// 공개키를 더블 해싱하여 SHA256,RIPEMD160를 각각 해주고
	version := byte(0x00)
	// 비트코인 주소를 의미하는 버전 접두어 0x00을 붙임

	return base58.CheckEncode(publicRIPEMD160, version)
	// 마지막으로 인코드를 해주면 주소가 생성된다.
}

// 공개키를 SHA256,RIPEMD160 해싱하고 반환하는 함수
// 공개키를 해싱 처리할 일이 트랜잭션에서 많기 때문에 따로 밖으로 빼줌
func HashPubKey(pubKey []byte) []byte {
	publicSHA256 := sha256.Sum256(pubKey)

	RIPEMD160Hasher := ripemd160.New()
	_, err := RIPEMD160Hasher.Write(publicSHA256[:])
	if err != nil {
		log.Panic(err)
	}

	return RIPEMD160Hasher.Sum(nil)

}

func main() {
	print("지갑주소: ")
	println(NewWallet().GetAddress())
	print("해시키: ")
	println(HashPubKey)
}
