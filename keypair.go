package searchpartykeys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"
)

type KeyPair struct {
	private ecdsa.PrivateKey
	public  *ecdsa.PublicKey
}

func NewKeyPair(key []byte) KeyPair {
	x, y := elliptic.P224().ScalarBaseMult(key)
	private := ecdsa.PrivateKey{
		D: new(big.Int).SetBytes(key),
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P224(),
			X:     x,
			Y:     y,
		},
	}
	return KeyPair{
		private: private,
		public:  private.Public().(*ecdsa.PublicKey),
	}
}

func (k *KeyPair) PrivateKey() []byte {
	return k.private.D.Bytes()
}

func (k *KeyPair) AdvKeyBytes() []byte {
	return k.public.X.Bytes()
}

func (k *KeyPair) HashedAdvKey() []byte {
	h := sha256.New()
	h.Write(k.AdvKeyBytes())
	return h.Sum(nil)
}
