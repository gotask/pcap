// sdpreader.go
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
)

type httpStreamFactory struct{}

func (h *httpStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	hstream := NewTcpStream(net, transport)
	tstream := &httpStream{hstream}
	tstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return tstream
}

type httpStream struct {
	*tcpStream
}

func (t *httpStream) run() {
	client := bufio.NewReader(&tcpReader{t.client, nil})
	server := bufio.NewReader(&tcpReader{t.server, nil})

	go func(r *bufio.Reader) {
		for {
			req, err := http.ReadRequest(r)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				log.Printf("HTTP-request", "HTTP/%s Request error: %s (%v,%+v)\n", t.ident, err, err, err)
				continue
			}
			body, err := ioutil.ReadAll(req.Body)
			s := len(body)
			if err != nil {
				log.Printf("HTTP-request-body", "Got body err: %s\n", err)
			}
			req.Body.Close()
			log.Printf("HTTP/%s Request: %s %s (body:%d):%s\n", t.ident, req.Method, req.URL, s, body)
		}
	}(client)
	go func(r *bufio.Reader) {
		for {
			res, err := http.ReadResponse(r, nil)
			var req string
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				log.Printf("HTTP-response", "HTTP/%s Response error: %s (%v,%+v)\n", t.rident, err, err, err)
				continue
			}
			body, err := ioutil.ReadAll(res.Body)
			s := len(body)
			if err != nil {
				log.Printf("HTTP-response-body", "HTTP/%s: failed to get body(parsed len:%d): %s\n", t.rident, s, err)
			}
			res.Body.Close()
			sym := ","
			if res.ContentLength > 0 && res.ContentLength != int64(s) {
				sym = "!="
			}
			contentType, ok := res.Header["Content-Type"]
			if !ok {
				contentType = []string{http.DetectContentType(body)}
			}
			encoding := res.Header["Content-Encoding"]
			log.Printf("HTTP/%s Response: %s URL:%s (%d%s%d%s) -> %s\n", t.rident, res.Status, req, res.ContentLength, sym, s, contentType, encoding)
			if err == nil {
				var r io.Reader
				r = bytes.NewBuffer(body)
				if len(encoding) > 0 && (encoding[0] == "gzip" || encoding[0] == "deflate") {
					r, err = gzip.NewReader(r)
					if err != nil {
						log.Printf("HTTP-gunzip", "Failed to gzip decode: %s", err)
					}
				}
				if err == nil {
					var out bytes.Buffer
					io.Copy(&out, r)
					if _, ok := r.(*gzip.Reader); ok {
						r.(*gzip.Reader).Close()
					}
					log.Printf("Response content: %s", out.Bytes())
				}
			}
		}
	}(server)
}

func goHttp(handle *pcap.Handle) {
	defer util.Run()()

	streamFactory := &httpStreamFactory{}
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
