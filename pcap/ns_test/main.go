package main

import (
	"fmt"
	"os"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
)

func openInNamespace(nsPath string) (<-chan gopacket.Packet, error) {
	targetNs, err := ns.GetNS(nsPath)
	if err != nil {
		return nil, errors.Wrapf(err, "can't get network namespace %s", nsPath)
	}
	defer targetNs.Close()

	var handle *pcap.Handle
	err = targetNs.Do(func(host ns.NetNS) error {
		var err error
		handle, err = pcap.OpenLive("eth0", 262144, true, pcap.BlockForever)
		if err != nil {
			return errors.Wrapf(err, "failed to open pcap to %s/%s", nsPath, "eth0")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// This actually spawns a goroutine, want to do this outside of the locked thread
	// (I think -- maybe every namespace needs its own OS thread.)
	return packetSource.Packets(), nil
}

func showPacket(nsPath string, packet gopacket.Packet) {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		fmt.Printf("%s: no network layer\n", nsPath)
		return
	}
	netFlow := netLayer.NetworkFlow()
	fmt.Printf("%s: %s -> %s\n", nsPath, netFlow.Src(), netFlow.Dst())
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Give two namespace paths.")
		return
	}
	ns1 := os.Args[1]
	ns2 := os.Args[2]

	ch1, err := openInNamespace(ns1)
	if err != nil {
		fmt.Println(err)
		return
	}
	ch2, err := openInNamespace(ns2)
	if err != nil {
		fmt.Println(err)
		return
	}

	for true {
		select {
		case p := <-ch1:
			showPacket(ns1, p)
		case p := <-ch2:
			showPacket(ns2, p)
		}
	}
}
