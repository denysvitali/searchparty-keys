package main

import (
	"encoding/base64"
	"fmt"

	searchpartykeys "github.com/denysvitali/searchparty-keys"
)

type BtAddressCmd struct {
	AdvKey string `arg:"positional,required" help:"The advertisement key to decode (base64)"`
}

func doBtAddress() {
	key, err := base64.StdEncoding.DecodeString(args.BtAddress.AdvKey)
	if err != nil {
		logger.Fatalf("failed to decode key: %v", err)
	}

	btAddr := searchpartykeys.BtAddrFromAdvKey(key)
	fmt.Printf("%02X:%02X:%02X:%02X:%02X:%02X\n", btAddr[0], btAddr[1], btAddr[2], btAddr[3], btAddr[4], btAddr[5])
}
