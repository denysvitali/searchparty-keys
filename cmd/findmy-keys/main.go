package main

import (
	"encoding/hex"
	"os"

	"github.com/alexflint/go-arg"
	"github.com/sirupsen/logrus"

	findmykeys "findmy-keys-decrypt"
)

type DecryptCmd struct {
	InputFile string `arg:"positional,required" help:"The input file to decrypt"`
	Key       string `arg:"--key,-k,env:DECRYPTION_KEY" help:"The key to use for decryption (hex)"`
}

type DecodeCmd struct {
	InputFile string `arg:"positional,required" help:"The curve point to decode"`
}

var args struct {
	Decrypt *DecryptCmd `arg:"subcommand:decrypt"`
	Decode  *DecodeCmd  `arg:"subcommand:decode"`
}

var logger = logrus.StandardLogger()

func main() {
	arg.MustParse(&args)

	if args.Decrypt != nil {
		f, err := os.Open(args.Decrypt.InputFile)
		if err != nil {
			logger.Fatalf("failed to open input file: %v", err)
		}
		keyBytes, err := hex.DecodeString(args.Decrypt.Key)
		if err != nil {
			logger.Fatalf("failed to decode key: %v", err)
		}
		decrypted, err := findmykeys.Decrypt(f, keyBytes)
		if err != nil {
			logger.Fatalf("failed to decrypt: %v", err)
		}
		_, _ = os.Stdout.Write(decrypted)
	} else if args.Decode != nil {
		f, err := os.Open(args.Decode.InputFile)
		if err != nil {
			logger.Fatalf("failed to open input file: %v", err)
		}
		decoded, err := findmykeys.Decode(f)
		if err != nil {
			logger.Fatalf("failed to decode: %v", err)
		}
		_, _ = os.Stdout.Write(decoded)
	} else {
		logger.Fatalf("no subcommand specified")
	}
}
