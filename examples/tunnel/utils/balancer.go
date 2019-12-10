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

const esp = 0x32
const mode1234 = 1234
const cryptoHeadLen = 24
const etherLen = types.EtherLen
const outerIPLen = types.IPv4MinLen
const authLen = 12
const cryptoTailLen = authLen + 2

type cryptHeader struct {
	SPI uint32
	SEQ uint32
	IV  [16]byte
}

type cryptoTail struct {
	paddingLen uint8
	nextIP     uint8
	Auth       [authLen]byte
}

const maxPacketSegment = 1484

func encrypt(currentPacket *packet.Packet, context0 flow.UserContext) bool {
	context := (context0).(*SContext)

	//context.setCipherKey([]byte("AES128Key-16Char"), true)

	currentPacket.ParseL3()
	dstMac, found := LBConfig.TunnelPort.neighCache.LookupMACForIPv4(LBConfig.TunnelPort.Subnet.IPv4.Addr)
	if !found {
		fmt.Println("Not found MAC address for IP", LBConfig.TunnelPort.Subnet.IPv4.Addr.String())
		LBConfig.TunnelPort.neighCache.SendARPRequestForIPv4(LBConfig.TunnelPort.Subnet.IPv4.Addr, LBConfig.InputPort.Subnet.IPv4.Addr, 0)
		return false
	}
	if currentPacket.Next != nil {
		fmt.Printf("encrypt BLOCK\n%x\nEND_BLOCK\n", currentPacket.Next.GetRawPacketBytes())
	}
	originalProtocol := currentPacket.Ether.EtherType
	if originalProtocol == types.SwapARPNumber {
		err := LBConfig.InputPort.neighCache.HandleIPv4ARPPacket(currentPacket)
		if err != nil {
			fmt.Println(err)
		}
		return false
	}
	//fmt.Println(fmt.Sprintf("Encrypt packet input [% x]", currentPacket.GetRawPacketBytes()))
	currentPacket.EncapsulateHead(etherLen, cryptoHeadLen+outerIPLen)
	currentPacket.ParseL3()
	currentPacket.Ether.DAddr = dstMac
	currentPacket.Ether.SAddr = LBConfig.TunnelPort.macAddress
	currentPacket.Ether.EtherType = types.SwapIPV4Number
	ipv4 := currentPacket.GetIPv4NoCheck()
	ipv4.SrcAddr = LBConfig.InputPort.Subnet.IPv4.Addr
	ipv4.DstAddr = LBConfig.TunnelPort.Subnet.IPv4.Addr
	ipv4.VersionIhl = 0x45
	ipv4.NextProtoID = esp
	length := currentPacket.GetPacketLen()
	paddingLength := uint8((16 - (length-(etherLen+outerIPLen+cryptoHeadLen)-cryptoTailLen)%16) % 16)
	newLength := length + uint(paddingLength) + cryptoTailLen
	//fmt.Println("L3", currentPacket.GetIPv4NoCheck())
	currentPacket.GetIPv4NoCheck().TotalLength = packet.SwapBytesUint16(uint16(newLength) - etherLen)
	currentPacket.EncapsulateTail(length, uint(paddingLength)+cryptoTailLen)

	currentCryptoHeader := (*cryptHeader)(currentPacket.StartAtOffset(etherLen + outerIPLen))
	currentCryptoHeader.SPI = packet.SwapBytesUint32(mode1234)
	nonce := make([]byte, 12)
	copy(currentCryptoHeader.IV[:], nonce)
	//fmt.Println("currentESPHeader", currentCryptoHeader)

	currentESPTail := (*cryptoTail)(currentPacket.StartAtOffset(uintptr(newLength) - cryptoTailLen))
	if paddingLength > 0 {
		*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(currentESPTail)) - uintptr(paddingLength))) = 578437695752307201
		if paddingLength > 8 {
			*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(currentESPTail)) - uintptr(paddingLength) + 8)) = 1157159078456920585
		}
	}
	currentESPTail.paddingLen = paddingLength
	switch originalProtocol {
	case types.SwapIPV4Number:
		currentESPTail.nextIP = 1
	case types.SwapARPNumber:
		currentESPTail.nextIP = 2
	}
	// Encryption
	EncryptionPart := (*[types.MaxLength]byte)(currentPacket.StartAtOffset(0))[etherLen+outerIPLen+cryptoHeadLen : newLength-authLen]
	//context.modeEnc.(SetIVer).SetIV(currentCryptoHeader.IV[:])
	//context.modeEnc.CryptBlocks(EncryptionPart, EncryptionPart)
	EncryptionPart = (*context.aesGCMEnc).Seal(nil, nonce, EncryptionPart, nil)
	// Authentication
	context.mac123.Reset()
	AuthPart := (*[types.MaxLength]byte)(currentPacket.StartAtOffset(0))[etherLen+outerIPLen : newLength-authLen]
	context.mac123.Write(AuthPart)
	copy(currentESPTail.Auth[:], context.mac123.Sum(nil))
	currentPacket.ParseL3()
	ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(currentPacket.GetIPv4NoCheck()))
	//fmt.Println("currentESPTail", currentESPTail)
	//fmt.Println(fmt.Sprintf("Encrypt packet result [% x]", currentPacket.GetRawPacketBytes()))
	return true
}

func decrypt(currentPacket *packet.Packet, context flow.UserContext) bool {
	//fmt.Println(fmt.Sprintf("Decrypt packet input [% x]", currentPacket.GetRawPacketBytes()))
	currentPacket.ParseL3()
	originalProtocol := currentPacket.Ether.EtherType
	if originalProtocol == types.SwapARPNumber {
		err := LBConfig.TunnelPort.neighCache.HandleIPv4ARPPacket(currentPacket)
		fmt.Println("DECRYPT ARP EXIT", currentPacket)
		if err != nil {
			fmt.Println(err)
		}
		return false
	}
	if currentPacket.Next != nil {
		fmt.Printf("decrypt BLOCK\n%x\nEND_BLOCK\n", currentPacket.Next.GetRawPacketBytes())
	}
	length := currentPacket.GetPacketLen()
	currentESPHeader := (*cryptHeader)(currentPacket.StartAtOffset(etherLen + outerIPLen))
	//fmt.Println("currentESPHeader", currentESPHeader)
	currentESPTail := (*cryptoTail)(unsafe.Pointer(currentPacket.StartAtOffset(uintptr(length) - cryptoTailLen)))
	//fmt.Println("currentESPTail", currentESPTail)
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
	currentPacket.ParseL3()
	ipv4 := currentPacket.GetIPv4NoCheck()
	dstMac, found := LBConfig.InputPort.neighCache.LookupMACForIPv4(ipv4.DstAddr)
	if !found {
		fmt.Println("Not found MAC address for IP", LBConfig.TunnelPort.Subnet.IPv4.Addr.String())
		LBConfig.InputPort.neighCache.SendARPRequestForIPv4(ipv4.DstAddr, ipv4.SrcAddr, 0)
		return false
	}
	currentPacket.Ether.DAddr = dstMac
	currentPacket.Ether.SAddr = LBConfig.InputPort.macAddress
	switch currentESPTail.nextIP {
	case 1:
		currentPacket.Ether.EtherType = types.SwapIPV4Number
	case 2:
		currentPacket.Ether.EtherType = types.SwapARPNumber
	}
	ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(currentPacket.GetIPv4NoCheck()))
	//fmt.Println(fmt.Sprintf("Decrypt packet result [% x]", currentPacket.GetRawPacketBytes()))
	return true
}

func decapsulationSPI123(currentAuth []byte, Auth [authLen]byte, iv [16]byte, ciphertext []byte, context0 flow.UserContext) bool {
	context := (context0).(*SContext)

	//context.setCipherKey([]byte("AES128Key-16Char"), true)

	context.mac123.Reset()
	context.mac123.Write(currentAuth)
	if bytes.Equal(context.mac123.Sum(nil)[0:12], Auth[:]) == false {
		fmt.Println("Decapsulate error check mac")
		return false
	}

	// Decryption
	if len(ciphertext) < aes.BlockSize || len(ciphertext)%aes.BlockSize != 0 {
		fmt.Println("Decapsulate error check BlockSize")
		return false
	}
	//context.modeDec.(SetIVer).SetIV(iv[:])
	//context.modeDec.CryptBlocks(ciphertext, ciphertext)
	nonce := iv[:12]
	ciphertext, _ = (*context.aesGCMDec).Open(nil, nonce, ciphertext, nil)
	return true
}
