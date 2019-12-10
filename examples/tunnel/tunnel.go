package main

import (
	"flag"
	"github.com/intel-go/nff-go/flow"
	lb "tunnel/utils"
)

func main() {
	cores := flag.String("cores", "", "Specify CPU cores to use.")
	configFile := flag.String("config", "config.json", "Specify config file name.")
	noscheduler := flag.Bool("no-scheduler", false, "Disable scheduler.")
	reassembly := flag.Bool("reassembly", true, "Enable Chain reassembly.")
	dpdkLogLevel := flag.String("dpdk", "--log-level=0", "Passes an arbitrary argument to dpdk EAL.")
	flag.Parse()

	// Read config
	flow.CheckFatal(lb.ReadConfig(*configFile))

	nffgoconfig := flow.Config{
		CPUList:          *cores,
		DPDKArgs:         []string{*dpdkLogLevel},
		DisableScheduler: *noscheduler,
		MemoryJumbo:      *reassembly,
	}

	flow.CheckFatal(flow.SystemInit(&nffgoconfig))
	lb.InitFlows()
	flow.CheckFatal(flow.SystemStart())
}
