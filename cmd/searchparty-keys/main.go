package main

import (
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/alexflint/go-arg"
	"github.com/sirupsen/logrus"

	searchpartykeys "github.com/denysvitali/searchparty-keys"
)

type DecryptCmd struct {
	InputFile string `arg:"positional,required" help:"The input file to decrypt"`
	Key       string `arg:"--key,-k,env:DECRYPTION_KEY" help:"The key to use for decryption (hex)"`
}

type DecodeCmd struct {
	InputFile string `arg:"positional,required" help:"The curve point to decode"`
}

type GenerateKeysCmd struct {
	InputFile  string `arg:"positional,required" help:"The input file to decrypt"`
	Key        string `arg:"--key,-k,env:DECRYPTION_KEY,required" help:"The key to use for decryption (hex)"`
	AmountKeys int    `arg:"--amount-keys,-a,required" help:"The amount of keys to generate"`
	KeyOffset  int    `arg:"--key-offset,-o" default:"0" help:"The offset of the key to be used"`
}

var args struct {
	Decrypt      *DecryptCmd      `arg:"subcommand:decrypt"`
	Decode       *DecodeCmd       `arg:"subcommand:decode"`
	GenerateKeys *GenerateKeysCmd `arg:"subcommand:generate-keys"`
}

var logger = logrus.StandardLogger()

func main() {
	arg.MustParse(&args)

	if args.Decrypt != nil {
		doDecrypt()
	} else if args.Decode != nil {
		doDecode()
	} else if args.GenerateKeys != nil {
		doGenerateKeys()
	} else {
		logger.Fatalf("no subcommand specified")
	}
}

func doDecrypt() {
	f, err := os.Open(args.Decrypt.InputFile)
	if err != nil {
		logger.Fatalf("failed to open input file: %v", err)
	}
	keyBytes, err := hex.DecodeString(args.Decrypt.Key)
	if err != nil {
		logger.Fatalf("failed to decode key: %v", err)
	}
	decrypted, err := searchpartykeys.Decrypt(f, keyBytes)
	if err != nil {
		logger.Fatalf("failed to decrypt: %v", err)
	}
	_, _ = os.Stdout.Write(decrypted)
}

func doDecode() {
	f, err := os.Open(args.Decode.InputFile)
	if err != nil {
		logger.Fatalf("failed to open input file: %v", err)
	}
	decoded, err := searchpartykeys.Decode(f)
	if err != nil {
		logger.Fatalf("failed to decode: %v", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(decoded); err != nil {
		logger.Fatalf("failed to encode: %v", err)
	}
}
