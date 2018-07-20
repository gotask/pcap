// tcp.go
package main

import (
	"fmt"
	"io"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
)

type tcpStreamFactory struct{}

func (h *tcpStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	hstream := NewTcpStream(net, transport)
	hstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return hstream
}

func NewTcpStream(net, transport gopacket.Flow) *tcpStream {
	var hstream *tcpStream
	if !reverse {
		hstream = &tcpStream{
			net:       net,
			transport: transport,
			client:    make(chan []byte, 1024),
			server:    make(chan []byte, 1024),
			ident:     fmt.Sprintf("%s:%s", net, transport),
			rident:    fmt.Sprintf("%s %s", net.Reverse(), transport.Reverse()),
		}
	} else {
		hstream = &tcpStream{
			net:       net,
			transport: transport,
			client:    make(chan []byte, 1024),
			server:    make(chan []byte, 1024),
			rident:    fmt.Sprintf("%s:%s", net, transport),
			ident:     fmt.Sprintf("%s %s", net.Reverse(), transport.Reverse()),
		}
	}

	return hstream
}

type tcpStream struct {
	net, transport gopacket.Flow
	reversed       bool
	client         chan []byte
	server         chan []byte
	ident          string
	rident         string
}

type tcpReader struct {
	bytes chan []byte
	data  []byte
}

func (h *tcpReader) Read(p []byte) (int, error) {
	ok := true
	for ok && len(h.data) == 0 {
		h.data, ok = <-h.bytes
	}
	if !ok || len(h.data) == 0 {
		return 0, io.EOF
	}

	l := copy(p, h.data)
	h.data = h.data[l:]
	return l, nil
}

func (t *tcpStream) run() {
	client := &tcpReader{t.client, nil}
	server := &tcpReader{t.server, nil}

	go func(r *tcpReader) {
		for {
			select {
			case data := <-r.bytes:
				if data == nil {
					return
				}
				log.Printf("%s length:%d", t.ident, len(data))
			}
		}
	}(client)
	go func(r *tcpReader) {
		for {
			select {
			case data := <-r.bytes:
				if data == nil {
					return
				}
				log.Printf("%s length:%d", t.rident, len(data))
			}
		}
	}(server)
}

func (t *tcpStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, acked reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	return true
}

func (t *tcpStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	dir, _, _, skip := sg.Info()
	length, _ := sg.Lengths()

	if skip == -1 {
		// this is allowed
	} else if skip != 0 {
		// Missing bytes in stream: do not even try to parse it
		return
	}

	data := sg.Fetch(length)
	if length > 0 {
		if !reverse {
			if dir == reassembly.TCPDirClientToServer {
				t.client <- data
			} else {
				t.server <- data
			}
		} else {
			if dir == reassembly.TCPDirClientToServer {
				t.server <- data
			} else {
				t.client <- data
			}
		}
	}
}

func (t *tcpStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	fmt.Printf("%s: Connection closed\n", t.ident)
	// do not remove the connection to allow last ACK
	close(t.client)
	close(t.server)
	return false
}

func goTcp(handle *pcap.Handle) {
	defer util.Run()()

	streamFactory := &tcpStreamFactory{}
	streamPool := reassembly.NewStreamPool(streamFactory)
	assembler := reassembly.NewAssembler(streamPool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
			continue
		}

		tcp, ok := packet.TransportLayer().(*layers.TCP)
		if !ok {
			continue
		}

		assembler.Assemble(packet.NetworkLayer().NetworkFlow(), tcp)
	}
}
