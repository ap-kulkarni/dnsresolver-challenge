package utils

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"os"
)

func GetRandomUint16() uint16 {
	randInt, err := rand.Int(rand.Reader, big.NewInt(65535))
	if err != nil {
		os.Exit(2)
	}
	return uint16(randInt.Uint64())
}

func ConvertUint16ToBytesArray(number uint16) []byte {
	numBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(numBytes, number)
	return numBytes
}

func GetUint16FromBytes(bytesToConvert []byte) uint16 {
	return binary.BigEndian.Uint16(bytesToConvert)
}
