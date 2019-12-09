package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"hash"
	"log"
)

type SContext struct {
	mac123  hash.Hash
	modeEnc cipher.BlockMode
	modeDec cipher.BlockMode
}

type SetIVer interface {
	SetIV([]byte)
}

func InitSContext() interface{} {
	var auth123Key = []byte("qqqqqqqqqqqqqqqqqqqq")
	var crypt123Key = []byte("AES128Key-16Char")
	block123, err := aes.NewCipher(crypt123Key)

	if err != nil {
		log.Fatal(err)
	}

	tempScalarIV := make([]byte, 16)

	n := new(SContext)
	n.mac123 = hmac.New(sha1.New, auth123Key)
	n.modeEnc = cipher.NewCBCEncrypter(block123, tempScalarIV)
	n.modeDec = cipher.NewCBCDecrypter(block123, tempScalarIV)
	return n
}

func (c SContext) Copy() interface{} {
	return InitSContext()
}

func (c SContext) Delete() {
}
