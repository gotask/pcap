// sdpreader.go
package main

import (
	"bytes"
	"compress/zlib"
	"io"
	"log"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
)

type ReqProto struct {
	ReqCmdId  uint32 `tag:"0" require:"true"`
	ReqCmdSeq uint32 `tag:"1"`
	ReqData   string `tag:"5"`
}
type RspProto struct {
	RspCmdId  uint32 `tag:"0" require:"true"`
	RspCmdSeq uint32 `tag:"1"`
	PushSeqId uint32 `tag:"2"`
	RspCode   int32  `tag:"5"`
	RspData   string `tag:"6"`
}

type sdpStreamFactory struct{}

func (h *sdpStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	hstream := NewTcpStream(net, transport)
	sstream := &sdpStream{hstream}
	sstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return sstream
}

type sdpStream struct {
	*tcpStream
}

func (t *sdpStream) run() {
	client := &tcpReader{t.client, nil}
	server := &tcpReader{t.server, nil}

	go func(r *tcpReader) {
		for {
			select {
			case data := <-r.bytes:
				if data == nil {
					return
				}
				r.data = append(r.data, data...)

				if len(r.data) < 4 {
					continue
				}
				msgLen := SdpLen(r.data)
				codeType := msgLen >> 24 & 0x01
				msgLen = msgLen & 0xFFFFFF
				if len(r.data) < int(msgLen) {
					continue
				}
				if msgLen <= 4 || msgLen > 1024*1024*10 {
					r.data = nil
					continue
				}
				rsp := &ReqProto{}
				if codeType > 0 {
					b := bytes.NewReader(r.data[4:msgLen])
					var out bytes.Buffer
					r, _ := zlib.NewReader(b)
					io.Copy(&out, r)

					Decode(rsp, out.Bytes())

				} else {
					Decode(rsp, r.data[4:msgLen])
				}
				rsp.ReqData = strconv.Itoa(int(len(rsp.ReqData)))
				log.Printf("%s %+v\n", t.ident, rsp)
				if len(r.data) == int(msgLen) {
					r.data = nil
					continue
				}
				r.data = r.data[msgLen:]
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
				r.data = append(r.data, data...)

				if len(r.data) < 4 {
					continue
				}
				msgLen := SdpLen(r.data)
				codeType := msgLen >> 24 & 0x01
				msgLen = msgLen & 0xFFFFFF
				if len(r.data) < int(msgLen) {
					continue
				}
				if msgLen <= 4 || msgLen > 1024*1024*10 {
					r.data = nil
					continue
				}
				rsp := &RspProto{}
				if codeType > 0 {
					b := bytes.NewReader(r.data[4:msgLen])
					var out bytes.Buffer
					r, _ := zlib.NewReader(b)
					io.Copy(&out, r)

					Decode(rsp, out.Bytes())

				} else {
					Decode(rsp, r.data[4:msgLen])
				}
				rsp.RspData = strconv.Itoa(int(len(rsp.RspData)))
				log.Printf("%s %+v\n", t.rident, rsp)
				if len(r.data) == int(msgLen) {
					r.data = nil
					continue
				}
				r.data = r.data[msgLen:]
			}
		}
	}(server)
}

func goSdp(handle *pcap.Handle) {
	defer util.Run()()

	streamFactory := &sdpStreamFactory{}
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
