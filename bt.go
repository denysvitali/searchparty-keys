package searchpartykeys

func BtAddrFromAdvKey(key []byte) []byte {
	return []byte{
		0b11<<6 | key[0],
		key[1],
		key[2],
		key[3],
		key[4],
		key[5],
	}
}
