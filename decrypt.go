package searchpartykeys

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"

	"howett.net/plist"
)

func Decrypt(f io.ReadSeeker, key []byte) ([]byte, error) {
	var r [][]byte
	err := plist.NewDecoder(f).Decode(&r)
	if err != nil {
		return nil, err
	}
	if len(r) != 3 {
		return nil, fmt.Errorf("invalid record")
	}
	nonce := r[0]
	tag := r[1]
	ciphertext := r[2]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}
	return aesGcm.Open(nil, nonce, append(ciphertext, tag...), nil)
}
