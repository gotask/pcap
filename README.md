# pcap
>> use libpcap cap net flow and decode
```
./pcap -e eth0 -bpf "tcp and port 80" -c "http"
./pcap -e eth0 -bpf "tcp and host 192.168.10.10" -c "sdp"
```
