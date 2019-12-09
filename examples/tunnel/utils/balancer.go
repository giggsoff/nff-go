// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tunnel

import (
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

func balancer(pkt *packet.Packet, ctx flow.UserContext) bool {
	return true
}
