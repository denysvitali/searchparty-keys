# searchparty-keys

This is a small package that can be used to derive Apple FindMy keys.  
It is used by [searchparty-go](https://github.com/denysvitali/searchparty-go).

## Prerequisites

- `OwnedBeacons` folder (from macOS / iOS)
- `Beacon Store` key (from macOS Keychain / iOS Keychain)

## Requirements

- Go

## Installation

```bash
go install github.com/denysvitali/searchparty-keys/cmd/searchparty-keys@latest
```

## Usage

See all the usage information by running `searchparty-keys -h`

```bash
read -s -r DECRYPTION_KEY
# Type the decryption key (BeaconStore) and press ENTER
searchparty-keys generate-keys -a 5 ./OwnedBeacons/B24F0C9F-42D6-4D38-B092-EFA8736A01B1.record
```

### Result

```plain
INFO[0000] Beacon: World Tag (a:/B24F0C9F-42D6-4D38-B092-EFA8736A01B1~#ABCDEF123456A800, 1.7.30) - Paired on 2024-06-27T17:28:25Z 
INFO[0000] Start time: 2024-06-28T20:36:06+02:00        
WARN[0000] Setting key offset to 102                    
Private key: [MASKED]
Advertisement key: bWWRtXpzYuukEJ2MBNACY3GrPJ7+4oErVBp0Dg==
Hashed adv key: /Z5xHE5LcnSnypZ1x7BYDItDwp9ON2fnarSY/6AAE+c=
BT Addr: ED:65:91:B5:7A:73


Private key: [MASKED]
Advertisement key: VebtsUnqKA/UtIbLhnWKgKvBhrBg/J/2CucD3A==
Hashed adv key: ngdFMZSE5oZQN8aMeftRZ4iFlLXHu/eX0O2iBZegl3E=
BT Addr: D5:E6:ED:B1:49:EA


Private key: [MASKED]
Advertisement key: Q/pmNxvYe1T52pie4y9iwpYd4sr6RDRnQwBtyg==
Hashed adv key: ML0bv/1eTh6Oc+VmIusm7TWb9OrZxyRIc4ka4libtqE=
BT Addr: C3:FA:66:37:1B:D8

# ...
```

## References

- [OpenHaystack](https://github.com/seemoo-lab/openhaystack/)
- Alexander Heinrich, Milan Stute, Tim Kornhuber, Matthias Hollick. **Who Can _Find My_ Devices? Security and Privacy of Apple's Crowd-Sourced Bluetooth Location Tracking System.** _Proceedings on Privacy Enhancing Technologies (PoPETs)_, 2021. [doi:10.2478/popets-2021-0045](https://doi.org/10.2478/popets-2021-0045) [📄 Paper](https://www.petsymposium.org/2021/files/papers/issue3/popets-2021-0045.pdf) [📄 Preprint](https://arxiv.org/abs/2103.02282).
- [FindMy.py](https://github.com/malmeloo/FindMy.py/)
- [YeapGuy/airtag-decryptor.swift](https://gist.github.com/YeapGuy/f473de53c2a4e8978bc63217359ca1e4)
