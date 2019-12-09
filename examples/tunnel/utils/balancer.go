// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tunnel

import (
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
)

const espHeadLen = 36
const etherLen = types.EtherLen
const outerIPLen = types.IPv4MinLen

type cryptHeader struct {
	SEQ uint32
	IV  [16]byte
	KEY [16]byte
}

func balancer(currentPacket *packet.Packet, context0 flow.UserContext) bool {
	context := (context0).(*SContext)
	length := currentPacket.GetPacketLen()
	paddingLength := uint8((16 - (length-(etherLen+outerIPLen+espHeadLen))%16) % 16)
	newLength := length + uint(paddingLength)
	currentPacket.GetIPv4NoCheck().TotalLength = packet.SwapBytesUint16(uint16(newLength) - etherLen)
	currentPacket.EncapsulateTail(length, uint(paddingLength))

	currentESPHeader := (*cryptHeader)(currentPacket.StartAtOffset(etherLen + outerIPLen))
	currentESPHeader.KEY = [16]byte{0x90, 0x9d, 0x78, 0xa8, 0x72, 0x70, 0x68, 0x00, 0x8f, 0xdc, 0x55, 0x73, 0xa3, 0x75, 0xb5, 0xa7}
	currentESPHeader.IV = [16]byte{0x90, 0x9d, 0x78, 0xa8, 0x72, 0x70, 0x68, 0x00, 0x8f, 0xdc, 0x55, 0x73, 0xa3, 0x75, 0xb5, 0xa7}

	// Encryption
	EncryptionPart := (*[types.MaxLength]byte)(currentPacket.StartAtOffset(0))[etherLen+outerIPLen+espHeadLen : newLength]
	context.modeEnc.(SetIVer).SetIV(currentESPHeader.IV[:])
	context.modeEnc.CryptBlocks(EncryptionPart, EncryptionPart)

	// Authentication
	context.mac123.Reset()
	AuthPart := (*[types.MaxLength]byte)(currentPacket.StartAtOffset(0))[etherLen+outerIPLen : newLength]
	context.mac123.Write(AuthPart)
	return true
}
