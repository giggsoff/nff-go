// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tunnel

import (
	"encoding/json"
	"os"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
)

type NetworkSubnet struct {
	IPv4 types.IPv4Subnet `json:"ipv4"`
	IPv6 types.IPv6Subnet `json:"ipv6"`
}

type IpPort struct {
	Index      uint16        `json:"index"`
	Subnet     NetworkSubnet `json:"subnet"`
	neighCache *packet.NeighboursLookupTable
	macAddress types.MACAddress
}

type LoadBalancerConfig struct {
	InputPort    IpPort        `json:"input-port"`
	TunnelPort   IpPort        `json:"tunnel-port"`
	TunnelSubnet NetworkSubnet `json:"tunnel-subnet"`
}

var LBConfig LoadBalancerConfig

func ReadConfig(fileName string) error {
	file, err := os.Open(fileName)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(file)

	err = decoder.Decode(&LBConfig)
	if err != nil {
		return err
	}

	return nil
}

func InitFlows() {
	ioFlow, err := flow.SetReceiver(LBConfig.InputPort.Index)
	flow.CheckFatal(err)
	flow.CheckFatal(flow.SetHandlerDrop(ioFlow, encrypt, SContext{}))
	flow.CheckFatal(flow.SetSender(ioFlow, LBConfig.TunnelPort.Index))
	ioFlow, err = flow.SetReceiver(LBConfig.TunnelPort.Index)
	flow.CheckFatal(err)
	flow.CheckFatal(flow.SetHandlerDrop(ioFlow, decrypt, SContext{}))
	flow.CheckFatal(flow.SetSender(ioFlow, LBConfig.InputPort.Index))

	LBConfig.InputPort.initPort()
	LBConfig.TunnelPort.initTunnelPort()
}

func (port *IpPort) initPort() {
	port.macAddress = flow.GetPortMACAddress(port.Index)
	port.neighCache = packet.NewNeighbourTable(port.Index, port.macAddress,
		func(ipv4 types.IPv4Address) bool {
			return LBConfig.TunnelSubnet.IPv4.CheckIPv4AddressWithinSubnet(ipv4)
		},
		func(ipv6 types.IPv6Address) bool {
			return LBConfig.TunnelSubnet.IPv6.CheckIPv6AddressWithinSubnet(ipv6)
		})
}

func (port *IpPort) initTunnelPort() {
	port.macAddress = flow.GetPortMACAddress(port.Index)
	port.neighCache = packet.NewNeighbourTable(port.Index, port.macAddress,
		func(ipv4 types.IPv4Address) bool {
			return ipv4 == LBConfig.InputPort.Subnet.IPv4.Addr
		},
		func(ipv6 types.IPv6Address) bool {
			return ipv6 == LBConfig.InputPort.Subnet.IPv6.Addr
		})
}
