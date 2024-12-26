package cryptography

import (
	"crypto/sha256"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSha256(t *testing.T) {
	testStrings := []string{
		"hello world",
		"1111111111111111111111",
		"dsichsdchiuhcuiciusdcihsdhsdchs",
		"csuidhchsacihsiuch ioscioashciojsocijoijicjoicjiodjcwiojcwioqj cwijiojwqiocjq",
	}

	for _, test := range testStrings {
		hashed, err := Sha256([]byte(test))
		properHashed := sha256.Sum256([]byte(test))

		assert.Nil(t, err)
		assert.Equal(t, properHashed, hashed)
	}
}
