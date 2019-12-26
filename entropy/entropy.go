package entropy

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

var (
	ErrEntropyLengthInvalid = errors.New("entropy length must be [128, 256] and a multiple of 32")
	ErrBitsChecksumLength   = errors.New("bits and checksum length error")
)

// Bits represents a byte slice of individual bits
type Bits []byte

// FromHex creates entropy bits from a hex string
func FromHex(input string) ([]byte, error) {
	bytes, err := hex.DecodeString(input)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// Random creates a random entropy of the given length
// 助记词长度和随机值位数之间的关系
// -----|----------|---------------|-------|
// bits | checksum | bits+checksum | words |
// -----|----------|---------------|-------|
// 128  |   4      | 132           | 12    |
// -----|----------|---------------|-------|
// 160  |   5      | 165           | 15    |
// -----|----------|---------------|-------|
// 192  |   6      | 198           | 18    |
// -----|----------|---------------|-------|
// 224  |   7      | 231           | 21    |
// -----|----------|---------------|-------|
// 256  |   8      | 264           | 24    |
// -----|----------|---------------|-------|
func Random(bitSize int) ([]byte, error) {
	if bitSize < 128 || bitSize > 256 || bitSize%32 > 0 {
		return nil, ErrEntropyLengthInvalid
	}

	bytes := make([]byte, bitSize/8)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

// CheckSum returns a slice of bits from the given entropy
func CheckSum(ent []byte) Bits {
	h := sha256.New()
	h.Write(ent)
	cs := h.Sum(nil)
	hashBits := bytesToBits(cs)
	num := len(ent) * 8 / 32
	return hashBits[:num]
}

// CheckSummed returns a bit slice of entropy with an appended check sum
func CheckSummed(ent []byte) Bits {
	cs := CheckSum(ent)
	bits := bytesToBits(ent)
	return append(bits, cs...)
}

func bytesToBits(bytes []byte) Bits {
	length := len(bytes)
	bits := make([]byte, length*8)
	for i := 0; i < length; i++ {
		b := bytes[i]
		for j := 0; j < 8; j++ {
			mask := byte(1 << uint8(j))
			bit := b & mask
			if bit == 0 {
				bits[(i*8)+8-(j+1)] = '0'
			} else {
				bits[(i*8)+8-(j+1)] = '1'
			}
		}
	}
	return bits
}

// 助记词长度和随机值位数之间的关系
// -----|----------|---------------|-------|
// bits | checksum | bits+checksum | words |
// -----|----------|---------------|-------|
// 128  |   4      | 132           | 12    |
// -----|----------|---------------|-------|
// 160  |   5      | 165           | 15    |
// -----|----------|---------------|-------|
// 192  |   6      | 198           | 18    |
// -----|----------|---------------|-------|
// 224  |   7      | 231           | 21    |
// -----|----------|---------------|-------|
// 256  |   8      | 264           | 24    |
// -----|----------|---------------|-------|
// length := len(bits) // bits+checksum
// chks := length / 32 // checksum bits
// bitsLen := length - chks // bits length
func BitsToBytes(bits Bits) (ent []byte, chksum Bits) {
	length := len(bits)
	if length%32 == 0 && length < 132 && length > 264 {
		return nil, nil
	}

	chks := length / 32
	bytesLen := (length - chks) / 8
	ent = make([]byte, 0, bytesLen)
	for k := 0; k < bytesLen; k++ {
		data := 0
		for i := 8 - 1; i >= 0; i-- {
			if bits[i+8*k] == 49 {
				data += 1 << (8 - i - 1)
			}
		}
		ent = append(ent, byte(data))
	}

	chksum = bits[length-chks:]
	return ent, chksum
}