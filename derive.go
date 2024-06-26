package searchpartykeys

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
)

func X963KDF(secret, sharedInfo []byte, keyLength int) ([]byte, error) {
	counter := uint32(1)
	result := make([]byte, 0, keyLength)
	var hash []byte
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

func CalculateAdvertisementKeys(d0, SK0 []byte, iterations int, offset int) (keys []KeyPair, err error) {
	P224N := elliptic.P224().Params().N
	if len(d0) != 28 {
		if len(d0) != 85 {
			return keys, fmt.Errorf("invalid length for d0: %d", len(d0))
		}
		d0 = d0[1:]
		d0 = d0[len(d0)-28:]
	}
	d0Int := new(big.Int).SetBytes(d0)

	SKp := SK0
	SKi := SK0

	for i := 0; i < offset; i++ {
		// Skip the first OFFSET keys
		SKi, err = X963KDF(SKp, []byte("update"), 32)
		if err != nil {
			return keys, err
		}
		SKp = SKi
	}

	var advKey []byte
	for i := 0; i < iterations; i++ {
		if i != 0 {
			SKi, err = X963KDF(SKp, []byte("update"), 32)
			if err != nil {
				return keys, err
			}
			SKp = SKi
		}

		// Derive (u_i, v_i)
		uv, err := X963KDF(SKi, []byte("diversify"), 72)
		if err != nil {
			return keys, err
		}
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

		// Calculate d_i = (d0 * ui) + vi
		key := new(big.Int).Mul(d0Int, uiInt)
		key.Add(key, viInt)
		key.Mod(key, P224N)
		advKey = key.Bytes()
		keys = append(keys, NewKeyPair(advKey))
	}
	return
}
