package main

import (
	"encoding/base64"
	"time"

	searchpartykeys "github.com/denysvitali/searchparty-keys"
)

type DecodeLocationInfoCmd struct {
	Key          string `arg:"--key,-k,env:DECRYPTION_KEY,required" help:"The key to use for decryption (hex)"`
	Secondary    bool   `arg:"--secondary" help:"Generate secondary keys"`
	Id           string `arg:"--id,required" help:"The key ID of the found location"`
	InputFile    string `arg:"positional,required" help:"The input file to decrypt"`
	LocationInfo string `arg:"positional,required" help:"The location info to decode"`
	UnixStart    int    `arg:"--unix-start" help:"Unix timestamp to start from"`
}

func doDecodeLocationInfo() {
	b, err := getBeacon(args.DecodeLocationInfo.InputFile, args.DecodeLocationInfo.Key)
	if err != nil {
		logger.Fatalf("failed to get beacon: %v", err)
	}

	var sk []byte
	var rotations int

	var startTime = time.Now()
	if args.DecodeLocationInfo.UnixStart > 0 {
		startTime = time.Unix(int64(args.DecodeLocationInfo.UnixStart), 0)
	}

	if args.DecodeLocationInfo.Secondary {
		sk = b.SecondarySharedSecret.Key.Data
		rotations = b.SecondaryRotations(startTime)
	} else {
		sk = b.SharedSecret.Key.Data
		rotations = b.PrimaryRotations(startTime)
	}

	kp, err := searchpartykeys.CalculateAdvertisementKeys(b.PrivateKey.Key.Data, sk, 50, rotations)
	if err != nil {
		logger.Fatalf("failed to calculate advertisement keys: %v", err)
	}

	locationInfoBytes, err := base64.StdEncoding.DecodeString(args.DecodeLocationInfo.LocationInfo)
	if err != nil {
		logger.Fatalf("failed to decode location info: %v", err)
	}
	for _, k := range kp {
		if base64.StdEncoding.EncodeToString(k.HashedAdvKey()) != args.DecodeLocationInfo.Id {
			continue
		}
		decoded, err := searchpartykeys.ParseLocationReport(&k, locationInfoBytes)
		if err != nil {
			continue
		}
		logger.Info(decoded)
		break
	}
}
