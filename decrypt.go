package searchpartykeys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/sirupsen/logrus"
	"howett.net/plist"
)

var logger = logrus.StandardLogger()

func debugPrint(msg string, arr []byte) {
	logger.Debugf("%s=%s\n", msg, hex.EncodeToString(arr))
}

type Key struct {
	Key KeyData `plist:"key"`
}

type KeyData struct {
	Data []byte `plist:"data"`
}

type Beacon struct {
	ProductId             int       `plist:"productId"`
	CloudkitMetadata      []byte    `plist:"cloudKitMetadata"`
	StableIdentifier      []string  `plist:"stableIdentifier"`
	PairingDate           time.Time `plist:"pairingDate"`
	BatteryLevel          int       `plist:"batteryLevel"`
	IsZeus                bool      `plist:"isZeus"`
	PrivateKey            Key       `plist:"privateKey"`
	Identifier            string    `plist:"identifier"`
	SystemVersion         string    `plist:"systemVersion"`
	SharedSecret          Key       `plist:"sharedSecret"`
	SecondarySharedSecret Key       `plist:"secondarySharedSecret"`
	Model                 string    `plist:"model"`
	VendorId              int       `plist:"vendorId"`
	PublicKey             Key       `plist:"publicKey"`
}

func Decrypt(f io.ReadSeeker, key []byte) (*Beacon, error) {
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

	debugPrint("key", key)
	debugPrint("nonce", nonce)
	debugPrint("tag", tag)
	debugPrint("ciphertext", ciphertext)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}
	decryptedBytes, err := aesGcm.Open(nil, nonce, append(ciphertext, tag...), nil)
	if err != nil {
		return nil, err
	}

	var beacon Beacon
	err = plist.NewDecoder(bytes.NewReader(decryptedBytes)).Decode(&beacon)
	return &beacon, err
}
