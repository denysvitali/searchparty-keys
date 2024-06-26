package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	searchpartykeys "github.com/denysvitali/searchparty-keys"
)

func doGenerateKeys() {
	f, err := os.Open(args.GenerateKeys.InputFile)
	if err != nil {
		logger.Fatalf("failed to open input file: %v", err)
	}

	keyBytes, err := hex.DecodeString(args.GenerateKeys.Key)
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

	// Generate keys
	keys, err := searchpartykeys.CalculateAdvertisementKeys(
		beacon.PrivateKey.Key.Data,
		beacon.SharedSecret.Key.Data,
		args.GenerateKeys.AmountKeys,
		args.GenerateKeys.KeyOffset,
	)
	if err != nil {
		logger.Fatalf("failed to generate keys: %v", err)
	}

	// Print keys
	for _, k := range keys {
		printKey(os.Stdout, &k)
		fmt.Fprintf(os.Stdout, "\n\n")
	}
}

func printKey(w io.Writer, pair *searchpartykeys.KeyPair) {
	fmt.Fprintf(w, "Private key: %s\n", base64.StdEncoding.EncodeToString(pair.PrivateKey()))
	fmt.Fprintf(w, "Advertisement key: %s\n", base64.StdEncoding.EncodeToString(pair.AdvKeyBytes()))
	fmt.Fprintf(w, "Hashed adv key: %s\n", base64.StdEncoding.EncodeToString(pair.HashedAdvKey()))

}
