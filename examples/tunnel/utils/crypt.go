package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"hash"
	"log"
)

type SContext struct {
	mac123    hash.Hash
	modeEnc   cipher.BlockMode
	modeDec   cipher.BlockMode
	aesGCMEnc *cipher.AEAD
	aesGCMDec *cipher.AEAD
}

type SetIVer interface {
	SetIV([]byte)
}

func (c SContext) setCipherKey(crypt123Key []byte, isEnc bool) {
	block123, err := aes.NewCipher(crypt123Key)

	if err != nil {
		log.Fatal(err)
	}
	if isEnc {
		enc, err := cipher.NewGCM(block123)
		if err != nil {
			panic(err.Error())
		}
		c.aesGCMEnc = &enc
	} else {
		dec, err := cipher.NewGCM(block123)
		if err != nil {
			panic(err.Error())
		}
		c.aesGCMDec = &dec
	}
}

func InitSContext() interface{} {
	var auth123Key = []byte("qqqqqqqqqqqqqqqqqqqq")
	var crypt123Key = []byte("AES128Key-16Char")
	block123, err := aes.NewCipher(crypt123Key)

	if err != nil {
		log.Fatal(err)
	}

	//tempScalarIV := make([]byte, 16)

	n := new(SContext)
	n.setCipherKey([]byte("AES128Key-16Char"), true)
	n.setCipherKey([]byte("AES128Key-16Char"), false)
	dec, _ := cipher.NewGCM(block123)
	n.aesGCMDec = &dec
	enc, _ := cipher.NewGCM(block123)
	n.aesGCMEnc = &enc
	n.mac123 = hmac.New(sha256.New, auth123Key)
	//n.modeEnc = cipher.NewCBCEncrypter(block123, tempScalarIV)
	//n.modeDec = cipher.NewCBCDecrypter(block123, tempScalarIV)
	return n
}

func (c SContext) Copy() interface{} {
	return InitSContext()
}

func (c SContext) Delete() {
}
