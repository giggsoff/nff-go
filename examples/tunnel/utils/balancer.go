// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tunnel

import (
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
	"unsafe"
)

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

type espTail struct {
	paddingLen uint8
	nextIP     uint8
	Auth       [authLen]byte
}

func balancer(currentPacket *packet.Packet, context0 flow.UserContext) bool {
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

	currentESPTail := (*espTail)(currentPacket.StartAtOffset(uintptr(newLength) - cryptoTailLen))
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
	context.modeEnc.(SetIVer).SetIV(currentCryptoHeader.IV[:])
	context.modeEnc.CryptBlocks(EncryptionPart, EncryptionPart)

	// Authentication
	context.mac123.Reset()
	AuthPart := (*[types.MaxLength]byte)(currentPacket.StartAtOffset(0))[etherLen+outerIPLen : newLength-authLen]
	context.mac123.Write(AuthPart)
	copy(currentESPTail.Auth[:], context.mac123.Sum(nil))
	return true
}
