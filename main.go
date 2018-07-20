package main

import (
	"flag"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	snapshot_len int32 = 65535
	promiscuous  bool  = true
)

var reverse bool
var IP string

func main() {
	device := flag.String("e", "eth0", "the name of the device")
	bpf := flag.String("bpf", "", "BPF filter;")
	re := flag.Bool("r", false, "reverse net flow dir")
	code := flag.String("c", "", "encode protocol")
	help := flag.Bool("h", false, "help")
	flag.Parse()

	if *help {
		flag.PrintDefaults()
		return
	}

	reverse = *re

	// Open device
	handle, err := pcap.OpenLive(*device, snapshot_len, promiscuous, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	var filter string = *bpf
	if filter != "" {
		err = handle.SetBPFFilter(filter)
		if err != nil {
			log.Fatal(err)
		}
	}

	if *code == "http" {
		goHttp(handle)
		return
	} else if *code == "sdp" {
		goSdp(handle)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		applicationLayer := packet.ApplicationLayer()

		if tcpLayer != nil && applicationLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			tcp, _ := tcpLayer.(*layers.TCP)
			log.Println("----------------------------------------------------------------------------")
			log.Println("IPv4: ", ip.SrcIP, ":", tcp.SrcPort, "->", ip.DstIP, ":", tcp.DstPort, " size:", len(applicationLayer.Payload()), " Seq:", tcp.Seq)
		}
	}
}
