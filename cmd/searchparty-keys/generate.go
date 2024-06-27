package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	searchpartykeys "github.com/denysvitali/searchparty-keys"
)

type GenerateKeysCmd struct {
	InputFile  string `arg:"positional,required" help:"The input file to decrypt"`
	Key        string `arg:"--key,-k,env:DECRYPTION_KEY,required" help:"The key to use for decryption (hex)"`
	AmountKeys int    `arg:"--amount-keys,-a,required" help:"The amount of keys to generate"`
	KeyOffset  int    `arg:"--key-offset,-o" default:"-1" help:"The offset of the key to be used"`
	Secondary  bool   `arg:"--secondary" help:"Generate secondary keys"`
	UnixStart  int    `arg:"--unix-start" help:"Unix timestamp to start from"`
}

func doGenerateKeys() {
	beacon, err := getBeacon(args.GenerateKeys.InputFile, args.GenerateKeys.Key)
	if err != nil {
		logger.Fatalf("failed to get beacon: %v", err)
	}

	logger.Infof("Beacon: %s (%s, %s) - Paired on %s",
		beacon.Model,
		beacon.StableIdentifier[0],
		beacon.SystemVersion,
		beacon.PairingDate.Format(time.RFC3339),
	)

	var startTime = time.Now()
	if args.GenerateKeys.UnixStart > 0 {
		startTime = time.Unix(int64(args.GenerateKeys.UnixStart), 0)
	}
	logger.Infof("Start time: %s", startTime.Format(time.RFC3339))

	var rotationCount int
	if args.GenerateKeys.Secondary {
		rotationCount = beacon.SecondaryRotations(startTime)
	} else {
		rotationCount = beacon.PrimaryRotations(startTime)
	}

	if args.GenerateKeys.KeyOffset < 0 {
		logger.Warnf("Setting key offset to %d", rotationCount)
		args.GenerateKeys.KeyOffset = rotationCount
	}

	var sk []byte
	if args.GenerateKeys.Secondary {
		sk = beacon.SecondarySharedSecret.Key.Data
	} else {
		sk = beacon.SharedSecret.Key.Data
	}

	// Generate keys
	keys, err := searchpartykeys.CalculateAdvertisementKeys(
		beacon.PrivateKey.Key.Data,
		sk,
		args.GenerateKeys.AmountKeys,
		args.GenerateKeys.KeyOffset,
	)
	if err != nil {
		logger.Fatalf("failed to generate keys: %v", err)
	}

	// Print keys
	for _, k := range keys {
		printKey(os.Stdout, &k)
		printBtAddr(os.Stdout, k.AdvKeyBytes())
		fmt.Fprintf(os.Stdout, "\n\n")
	}
}

func printBtAddr(stdout *os.File, key []byte) {
	btAddr := searchpartykeys.BtAddrFromAdvKey(key)
	fmt.Fprintf(stdout, "BT Addr: %s\n", formatAddr(btAddr))
}

// formatAddr formats a Bluetooth address as a string.
func formatAddr(addr []byte) any {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5])
}

func getBeacon(beaconFile string, hexKey string) (*searchpartykeys.Beacon, error) {
	f, err := os.Open(beaconFile)
	if err != nil {
		logger.Fatalf("failed to open input file: %v", err)
	}

	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		logger.Fatalf("failed to decode key: %v", err)
	}

	// Decrypt file
	decryptedBytes, err := searchpartykeys.Decrypt(f, keyBytes)
	if err != nil {
		logger.Fatalf("failed to decrypt file: %v", err)
	}

	// Decode file
	beacon, err := searchpartykeys.Decode(bytes.NewReader(decryptedBytes))
	if err != nil {
		logger.Fatalf("failed to decode file: %v", err)
	}
	return beacon, err
}

func printKey(w io.Writer, pair *searchpartykeys.KeyPair) {
	fmt.Fprintf(w, "Private key: %s\n", base64.StdEncoding.EncodeToString(pair.PrivateKey()))
	fmt.Fprintf(w, "Advertisement key: %s\n", base64.StdEncoding.EncodeToString(pair.AdvKeyBytes()))
	fmt.Fprintf(w, "Hashed adv key: %s\n", base64.StdEncoding.EncodeToString(pair.HashedAdvKey()))

}
