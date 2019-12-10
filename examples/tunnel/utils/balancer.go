// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tunnel

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
	"unsafe"
)

const mode1234 = 1234
const cryptoHeadLen = 36
const etherLen = types.EtherLen
const outerIPLen = types.IPv4MinLen
const authLen = 12
const cryptoTailLen = authLen + 2

type cryptHeader struct {
	SEQ uint32
	IV  [16]byte
	KEY [16]byte
}

type cryptoTail struct {
	paddingLen uint8
	nextIP     uint8
	Auth       [authLen]byte
}

func encrypt(currentPacket *packet.Packet, context0 flow.UserContext) bool {
	fmt.Println("Encrypt packet input", currentPacket.GetRawPacketBytes())
	currentPacket.EncapsulateHead(etherLen, outerIPLen+cryptoHeadLen)
	context := (context0).(*SContext)
	length := currentPacket.GetPacketLen()
	paddingLength := uint8((16 - (length-(etherLen+outerIPLen+cryptoHeadLen)-cryptoTailLen)%16) % 16)
	newLength := length + uint(paddingLength) + cryptoTailLen
	currentPacket.GetIPv4NoCheck().TotalLength = packet.SwapBytesUint16(uint16(newLength) - etherLen)
	currentPacket.EncapsulateTail(length, uint(paddingLength)+cryptoTailLen)

	currentCryptoHeader := (*cryptHeader)(currentPacket.StartAtOffset(etherLen + outerIPLen))
	currentCryptoHeader.KEY = [16]byte{0x90, 0x9d, 0x78, 0xa8, 0x72, 0x70, 0x68, 0x00, 0x8f, 0xdc, 0x55, 0x73, 0xa3, 0x75, 0xb5, 0xa7}
	currentCryptoHeader.IV = [16]byte{0x90, 0x9d, 0x78, 0xa8, 0x72, 0x70, 0x68, 0x00, 0x8f, 0xdc, 0x55, 0x73, 0xa3, 0x75, 0xb5, 0xa7}

	currentESPTail := (*cryptoTail)(currentPacket.StartAtOffset(uintptr(newLength) - cryptoTailLen))
	if paddingLength > 0 {
		*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(currentESPTail)) - uintptr(paddingLength))) = 578437695752307201
		if paddingLength > 8 {
			*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(currentESPTail)) - uintptr(paddingLength) + 8)) = 1157159078456920585
		}
	}
	currentESPTail.paddingLen = paddingLength
	currentESPTail.nextIP = types.IPNumber
	// Encryption
	EncryptionPart := (*[types.MaxLength]byte)(currentPacket.StartAtOffset(0))[etherLen+outerIPLen+cryptoHeadLen : newLength-authLen]
	fmt.Println("Input", EncryptionPart)
	context.modeEnc.(SetIVer).SetIV(currentCryptoHeader.IV[:])
	context.modeEnc.CryptBlocks(EncryptionPart, EncryptionPart)

	// Authentication
	context.mac123.Reset()
	AuthPart := (*[types.MaxLength]byte)(currentPacket.StartAtOffset(0))[etherLen+outerIPLen : newLength-authLen]
	context.mac123.Write(AuthPart)
	copy(currentESPTail.Auth[:], context.mac123.Sum(nil))
	fmt.Println("Encrypt packet result", currentPacket.GetRawPacketBytes())
	return true
}

func decrypt(currentPacket *packet.Packet, context flow.UserContext) bool {
	fmt.Println("Decrypt packet input", currentPacket.GetRawPacketBytes())
	length := currentPacket.GetPacketLen()
	currentESPHeader := (*cryptHeader)(currentPacket.StartAtOffset(etherLen + outerIPLen))
	currentESPTail := (*cryptoTail)(unsafe.Pointer(currentPacket.StartAtOffset(uintptr(length) - cryptoTailLen)))
	if currentESPHeader.KEY != currentESPHeader.IV {
		fmt.Println("currentESPHeader check error")
		fmt.Println("currentESPHeader KEY", currentESPHeader.KEY)
		fmt.Println("currentESPHeader IV", currentESPHeader.IV)
		return false
	}
	if length-authLen < etherLen+outerIPLen+cryptoHeadLen || length-authLen < etherLen+outerIPLen {
		fmt.Println("Length check error", length)
		return false
	}
	// Security Association
	encryptionPart := (*[types.MaxLength]byte)(unsafe.Pointer(currentPacket.StartAtOffset(0)))[etherLen+outerIPLen+cryptoHeadLen : length-authLen]
	authPart := (*[types.MaxLength]byte)(unsafe.Pointer(currentPacket.StartAtOffset(0)))[etherLen+outerIPLen : length-authLen]
	if decapsulationSPI123(authPart, currentESPTail.Auth, currentESPHeader.IV, encryptionPart, context) == false {
		fmt.Println("Decapsulate error")
		return false
	}
	// Decapsulate
	currentPacket.DecapsulateHead(etherLen, outerIPLen+cryptoHeadLen)
	currentPacket.DecapsulateTail(length-cryptoTailLen-uint(currentESPTail.paddingLen), uint(currentESPTail.paddingLen)+cryptoTailLen)
	fmt.Println("Decrypt packet result", currentPacket.GetRawPacketBytes())
	return true
}

func decapsulationSPI123(currentAuth []byte, Auth [authLen]byte, iv [16]byte, ciphertext []byte, context0 flow.UserContext) bool {
	context := (context0).(*SContext)

	context.mac123.Reset()
	context.mac123.Write(currentAuth)
	if bytes.Equal(context.mac123.Sum(nil)[0:12], Auth[:]) == false {
		return false
	}

	// Decryption
	if len(ciphertext) < aes.BlockSize || len(ciphertext)%aes.BlockSize != 0 {
		return false
	}
	context.modeDec.(SetIVer).SetIV(iv[:])
	context.modeDec.CryptBlocks(ciphertext, ciphertext)
	return true
}
