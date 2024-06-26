package searchpartykeys

import (
	"io"

	"howett.net/plist"
)

func Decode(f io.ReadSeeker) (*Beacon, error) {
	var b Beacon
	err := plist.NewDecoder(f).Decode(&b)
	return &b, err
}
