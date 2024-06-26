package searchpartykeys

type Payload struct {
	LocationInfo []string `json:"locationInfo"`
	Id           string   `json:"id"`
}

type Locations struct {
	LocationPayload []Payload `json:"locationPayload"`
	ConfigVersion   int       `json:"configVersion"`
	StatusCode      string    `json:"statusCode"`
}

type Info struct {
	LocationTs int64  `json:"locationTs"`
	Location   string `json:"location"`
	Fmt        int    `json:"fmt"`
}

type P struct {
	LocationInfo []Info `json:"locationInfo"`
	Id           string `json:"id"`
}

type DeviceLocations struct {
	LocationPayload []P    `json:"locationPayload"`
	ConfigVersion   int    `json:"configVersion"`
	StatusCode      string `json:"statusCode"`
}

type SearchResponse struct {
	ConfigVersion        int             `json:"configVersion"`
	AcsnLocations        Locations       `json:"acsnLocations"`
	OwnedDeviceLocations DeviceLocations `json:"ownedDeviceLocations"`
}
