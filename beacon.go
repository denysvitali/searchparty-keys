package searchpartykeys

import "time"

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
