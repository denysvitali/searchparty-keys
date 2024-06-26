package searchpartykeys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"

	"github.com/sirupsen/logrus"
)

const coreDataTsDiff = 978307200

type Report struct {
	Time         time.Time
	Confidence   byte
	HashedPubKey string
}

var logger = logrus.StandardLogger()

func ParseLocationReport(key *KeyPair, content []byte) (*Report, error) {
	if len(content) != 4+1+57+10+16 {
		return nil, fmt.Errorf("invalid report length")
	}

	ts := time.Unix(int64(binary.BigEndian.Uint32(content[0:4])+coreDataTsDiff), 0)
	confidence := content[4]
	curveBytes := content[5:62]

	if curveBytes[0] != 0x04 {
		return nil, fmt.Errorf("invalid curve byte")
	}
	pubKey := curveBytes[1:]

	x := new(big.Int).SetBytes(pubKey[:28])
	y := new(big.Int).SetBytes(pubKey[28:])

	ephKey := &ecdsa.PublicKey{Curve: elliptic.P224(), X: x, Y: y}
	sharedKey, _ := ephKey.Curve.ScalarMult(ephKey.X, ephKey.Y, key.PrivateKey())
	sharedKeyBytes := sharedKey.Bytes()

	toHash := append(sharedKeyBytes, byte(0), byte(0), byte(0), byte(1))
	toHash = append(toHash, curveBytes...)

	symmetricKey := sha256Hash(toHash)
	decryptionKey := symmetricKey[:16]
	iv := symmetricKey[16:]

	startIdx := 62
	encData := content[startIdx : startIdx+8]
	tag := content[startIdx+8:]

	decrypted, err := decrypt(encData, decryptionKey, iv, tag)
	if err != nil {
		return nil, err
	}

	logger.Debugf("Decrypted: %v", decrypted)

	lat := binary.BigEndian.Uint32(decrypted[0:4])
	lng := binary.BigEndian.Uint32(decrypted[4:8])
	acc := decrypted[8]
	status := decrypted[9]

	logger.Debugf("Location: %f, %f, accuracy: %d, status: %d", float32(lat)/1e7, float32(lng)/1e7, acc, status)

	return &Report{
		Time:       ts,
		Confidence: confidence,
	}, nil
}

func decrypt(encData, key, iv, tag []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, err
	}
	return aesgcm.Open(nil, iv, append(encData, tag...), nil)
}

func sha256Hash(hash []byte) []byte {
	h := sha256.Sum256(hash)
	return h[:]
}
