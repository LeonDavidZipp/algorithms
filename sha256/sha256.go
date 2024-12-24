package sha256

import (
	"bytes"
	"encoding/binary"
	"math/bits"
)

func pad(input []byte) ([]byte, error) {
	// Padding: The input data is first padded so its length is a specific value modulo 512 in bit length.
	// It’s achieved by adding a ‘1’ bit, followed by enough ‘0’ bits to reach the required length minus 64 bits.
	// Finally, the original length of the data is added as a 64-bit value at the end.

	// get lenBits, the actual data length in bits
	l := int64(len(input)) * 8   // to account for actual bit length
	lenBits := new(bytes.Buffer) // bit len: 64; bytes len: 8
	if err := binary.Write(lenBits, binary.BigEndian, l); err != nil {
		return []byte{}, err
	}

	// Append the '1' bit followed by '0' bits
	padded := append(input, 0x80)

	// Calculate the number of zero bytes to append
	paddingLength := (64 - (len(padded)+8)%64) % 64

	// Append the zero bytes
	padded = append(padded, make([]byte, paddingLength)...)

	// Append the original length as a 64-bit value
	padded = append(padded, lenBits.Bytes()...)

	return padded, nil
}

func split(input []byte) [][64]byte {
	numBlocks := len(input) >> 6 // 64 bytes per block

	blocks := make([][64]byte, numBlocks)
	for i := 0; i < numBlocks; i++ {
		copy(blocks[i][:], input[i*64:(i+1)*64])
	}

	return blocks
}

func hashes() [8]uint32 {
	// Initialize hash values
	return [8]uint32{
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	}
}

func spices() [64]uint32 {
	// Initialize array of round constants
	return [64]uint32{
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	}
}

// encrypts input
func Sha256(input []byte) ([32]byte, error) {
	// Padding: append a '1' bit, followed by '0' bits, and the original length of the
	// data as a 64-bit value such that the length is a specific value modulo 512 in bit length
	padded, err := pad(input)
	if err != nil {
		return [32]byte{}, err
	}

	// Split the padded data into 512-bit blocks
	blocks := split(padded)

	// Initialize hash values
	hashes := hashes()

	// Initialize array of round constants
	spices := spices()

	for _, block := range blocks {
		// Initialize registers with the current hash values
		a, b, c, d, e, f, g, h := hashes[0], hashes[1], hashes[2], hashes[3], hashes[4], hashes[5], hashes[6], hashes[7]

		// Prepare the message schedule
		var W [64]uint32
		for t := 0; t < 16; t++ {
			W[t] = binary.BigEndian.Uint32(block[t*4 : (t+1)*4])
		}
		for t := 16; t < 64; t++ {
			s0 := bits.RotateLeft32(W[t-15], -7) ^ bits.RotateLeft32(W[t-15], -18) ^ (W[t-15] >> 3)
			s1 := bits.RotateLeft32(W[t-2], -17) ^ bits.RotateLeft32(W[t-2], -19) ^ (W[t-2] >> 10)
			W[t] = W[t-16] + s0 + W[t-7] + s1
		}

		// Compression function main loop
		for t := 0; t < 64; t++ {
			T1 := h + (bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)) + ((e & f) ^ (^e & g)) + spices[t] + W[t]
			T2 := (bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)) + ((a & b) ^ (a & c) ^ (b & c))
			h = g
			g = f
			f = e
			e = d + T1
			d = c
			c = b
			b = a
			a = T1 + T2
		}

		// Update the hash values
		hashes[0] += a
		hashes[1] += b
		hashes[2] += c
		hashes[3] += d
		hashes[4] += e
		hashes[5] += f
		hashes[6] += g
		hashes[7] += h
	}

	// Convert the final hash values to bytes
	var hash [32]byte
	for i, h := range hashes {
		binary.BigEndian.PutUint32(hash[i*4:], h)
	}

	return hash, nil
}
