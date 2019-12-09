// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tunnel

import (
	"fmt"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
)

func arpHandler(pkt *packet.Packet, ctx flow.UserContext) bool {
	pkt.ParseL3()
	protocol := pkt.Ether.EtherType

	if protocol == types.SwapARPNumber {
		err := LBConfig.TunnelPort.neighCache.HandleIPv4ARPPacket(pkt)
		if err != nil {
			fmt.Println(err)
		}
		return false
	} else if protocol == types.SwapIPV4Number {
		ipv4 := pkt.GetIPv4NoCheck()
		if !LBConfig.TunnelSubnet.IPv4.CheckIPv4AddressWithinSubnet(ipv4.DstAddr) {
			fmt.Println("Received IPv4 packet that is not targeted at balanced subnet",
				LBConfig.TunnelSubnet.IPv4.String(),
				"it is targeted at address", ipv4.DstAddr.String(), "instead. Packet dropped.")
			return false
		}
		workerMAC, found := LBConfig.InputPort.neighCache.LookupMACForIPv4(ipv4.DstAddr)
		if !found {
			fmt.Println("Not found MAC address for IP", ipv4.DstAddr.String())
			LBConfig.InputPort.neighCache.SendARPRequestForIPv4(ipv4.DstAddr, ipv4.SrcAddr, 0)
			return false
		}

		if !pkt.EncapsulateHead(types.EtherLen, types.IPv4MinLen+types.GRELen) {
			fmt.Println("EncapsulateHead returned error")
			return false
		}
		pkt.ParseL3()

		// Fill up L2
		pkt.Ether.SAddr = LBConfig.TunnelPort.macAddress
		pkt.Ether.DAddr = workerMAC
		pkt.Ether.EtherType = types.SwapIPV4Number
		gre := pkt.GetGREForIPv4()
		gre.Flags = 0
		gre.NextProto = protocol

		return true

	}
	return true
}
