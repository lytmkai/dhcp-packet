package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// 替换为你实际的网卡名称，可以通过 pcap.FindAllDevs() 获取
	deviceName := "\\Device\\NTPNP_PCI0008" 
	snapshotLen := int32(65535)
	promiscuous := true
	timeout := pcap.BlockForever

	handle, err := pcap.OpenLive(deviceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal("打开网卡失败:", err)
	}
	defer handle.Close()

	// 过滤 DHCPv4 (端口 67/68) 和 DHCPv6 (端口 546/547)
	err = handle.SetBPFFilter("udp and (port 67 or port 68 or port 546 or port 547)")
	if err != nil {
		log.Fatal("设置过滤器失败:", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("[*] 正在监听 DHCP / DHCPv6 流量...")

	for packet := range packetSource.Packets() {
		// 解析 IPv4 DHCP
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			if (udp.SrcPort == 67 || udp.DstPort == 67) {
				fmt.Println("\n[捕获到 IPv4 DHCP 报文]")
				fmt.Printf("源端口: %d -> 目的端口: %d\n", udp.SrcPort, udp.DstPort)
				// 打印应用层载荷，DHCP 的具体 Option 都在这里
				fmt.Printf("载荷内容: %x\n", udp.Payload)
			}
			// 解析 IPv6 DHCPv6
			if (udp.SrcPort == 547 || udp.DstPort == 547) {
				fmt.Println("\n[捕获到 IPv6 DHCPv6 报文]")
				if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
					ipv6, _ := ipv6Layer.(*layers.IPv6)
					fmt.Printf("源 IPv6: %s -> 目的 IPv6: %s\n", ipv6.SrcIP, ipv6.DstIP)
				}
				fmt.Printf("载荷内容: %x\n", udp.Payload)
			}
		}
	}
}
