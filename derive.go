package searchpartykeys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
)

func X963KDF(secret, sharedInfo []byte, keyLength int) ([]byte, error) {
	h := sha256.New
	hashSize := h().Size()
	counter := uint32(1)
	result := make([]byte, 0, keyLength)
	var hash = make([]byte, 0, hashSize)
	for len(result) < keyLength {
		h := sha256.New()
		counterBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(counterBytes, counter)
		h.Write(secret)
		h.Write(counterBytes)
		h.Write(sharedInfo)
		hash = h.Sum(nil)
		result = append(result, hash...)
		counter++
	}

	return result[:keyLength], nil
}

func debugByteArr(title string, b []byte) {
	//fmt.Printf("%10s [B64] (%d): %s\n", title, len(b), base64.StdEncoding.EncodeToString(b))
	//fmt.Printf("%10s [HEX] (%d): %s\n", title, len(b), fmt.Sprintf("%x", b))
}

func CalculateAdvertisementKeys(d0, SK0 []byte, iterations int) (key KeyPair, err error) {
	P224N := elliptic.P224().Params().N

	if len(d0) != 28 {
		if len(d0) != 85 {
			return key, fmt.Errorf("invalid length for d0: %d", len(d0))
		}
		d0 = d0[1:]
		d0 = d0[len(d0)-28:]
	}
	debugByteArr("d0", d0)
	d0Int := new(big.Int).SetBytes(d0)

	SKp := SK0
	SKi := SK0
	debugByteArr("SK0", SK0)

	var advKey []byte
	for i := 0; i < iterations; i++ {
		if i != 0 {
			SKi, err = X963KDF(SKp, []byte("update"), 32)
			if err != nil {
				return key, err
			}
			SKp = SKi
		}
		debugByteArr("SKi", SKi)

		// Derive (u_i, v_i)
		uv, err := X963KDF(SKi, []byte("diversify"), 72)
		if err != nil {
			return key, err
		}
		debugByteArr("uv", uv)
		u := uv[:36]
		v := uv[36:]

		p224MinusOne := big.NewInt(0).Sub(P224N, big.NewInt(1))

		// Convert d0, ui, vi to big.Int

		uiInt := new(big.Int).SetBytes(u)
		uiInt.Mod(uiInt, p224MinusOne)
		uiInt.Add(uiInt, big.NewInt(1))

		viInt := new(big.Int).SetBytes(v)
		viInt.Mod(viInt, p224MinusOne)
		viInt.Add(viInt, big.NewInt(1))

		logger.Debugf("d0: %s", d0Int.Text(10))
		logger.Debugf("ui: %s", uiInt.Text(10))
		logger.Debugf("vi: %s", viInt.Text(10))

		// Calculate d_i = (d0 * ui) + vi
		key := new(big.Int).Mul(d0Int, uiInt)
		key.Add(key, viInt)
		key.Mod(key, P224N)
		debugByteArr("key", key.Bytes())
		advKey = key.Bytes()
	}
	return newKeyPair(advKey), nil
}

type KeyPair struct {
	private ecdsa.PrivateKey
	public  *ecdsa.PublicKey
}

func newKeyPair(key []byte) KeyPair {
	privInt := new(big.Int).SetBytes(key)
	logger.Debugf("privInt: %s", privInt.Text(10))
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

func (k *KeyPair) AdvKeyBytes() []byte {
	return k.public.X.Bytes()
}

func (k *KeyPair) HashedAdvKey() []byte {
	h := sha256.New()
	h.Write(k.AdvKeyBytes())
	return h.Sum(nil)
}
