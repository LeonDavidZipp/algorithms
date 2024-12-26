package cryptography

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPrevNextPow2(t *testing.T) {
	// prev
	assert.Equal(t, uint32(0), prevPow2(0))
	assert.Equal(t, uint32(1), prevPow2(1))
	assert.Equal(t, uint32(2), prevPow2(2))
	assert.Equal(t, uint32(2), prevPow2(3))
	assert.Equal(t, uint32(4), prevPow2(4))
	assert.Equal(t, uint32(4), prevPow2(5))
	assert.Equal(t, uint32(4), prevPow2(6))
	assert.Equal(t, uint32(4), prevPow2(7))
	assert.Equal(t, uint32(8), prevPow2(8))
	assert.Equal(t, uint32(8), prevPow2(9))
	assert.Equal(t, uint32(16), prevPow2(16))
	assert.Equal(t, uint32(16), prevPow2(23))
	assert.Equal(t, uint32(32), prevPow2(32))
	assert.Equal(t, uint32(32), prevPow2(33))
	assert.Equal(t, uint32(32), prevPow2(63))

	// next
	assert.Equal(t, uint32(0), nextPow2(0))
	assert.Equal(t, uint32(1), nextPow2(1))
	assert.Equal(t, uint32(2), nextPow2(2))
	assert.Equal(t, uint32(4), nextPow2(3))
	assert.Equal(t, uint32(4), nextPow2(4))
	assert.Equal(t, uint32(8), nextPow2(5))
	assert.Equal(t, uint32(8), nextPow2(6))
	assert.Equal(t, uint32(8), nextPow2(7))
	assert.Equal(t, uint32(8), nextPow2(8))
	assert.Equal(t, uint32(16), nextPow2(9))
	assert.Equal(t, uint32(16), nextPow2(16))
	assert.Equal(t, uint32(32), nextPow2(17))
	assert.Equal(t, uint32(32), nextPow2(32))
	assert.Equal(t, uint32(64), nextPow2(33))
	assert.Equal(t, uint32(64), nextPow2(63))
}
