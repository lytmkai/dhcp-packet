package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// 1. 获取本机所有网卡设备
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal("获取网卡列表失败:", err)
	}

	// 2. 打印网卡列表供用户选择
	fmt.Println("发现以下网卡设备：")
	for i, device := range devices {
		fmt.Printf("[%d] %s\n", i+1, device.Name)
		// 打印描述和IP地址，方便用户辨认
		if device.Description != "" {
			fmt.Printf("    描述: %s\n", device.Description)
		}
		for _, address := range device.Addresses {
			if address.IP != nil {
				fmt.Printf("    IP地址: %s\n", address.IP)
			}
		}
		fmt.Println()
	}

	// 3. 接收用户输入并选择网卡
	fmt.Print("请输入要抓包的网卡编号: ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	selection, err := strconv.Atoi(input)
	if err != nil || selection < 1 || selection > len(devices) {
		log.Fatal("无效的网卡编号！")
	}

	// 获取用户选中的网卡对象
	selectedDevice := devices[selection-1]
	fmt.Printf("\n已选择网卡: %s (%s)\n\n", selectedDevice.Name, selectedDevice.Description)

	// 4. 打开选中的网卡并开始抓包
	var (
		snapshotLen int32         = 65535            // 捕获数据包的最大长度
		promiscuous bool          = true             // 是否开启混杂模式
		timeout     time.Duration = 30 * time.Second // 读取超时时间
		handle      *pcap.Handle
	)

	// 打开网卡
	handle, err = pcap.OpenLive(selectedDevice.Name, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal("打开网卡失败:", err)
	}
	defer handle.Close()

	// 设置 BPF 过滤器，只抓取 DHCP (IPv4) 和 DHCPv6 的流量
	// 端口 67/68 是 DHCPv4，端口 546/547 是 DHCPv6
	err = handle.SetBPFFilter("udp and (port 67 or port 68 or port 546 or port 547)")
	if err != nil {
		log.Fatal("设置过滤器失败:", err)
	}

	fmt.Println("[*] 开始监听 DHCP / DHCPv6 流量，按 Ctrl+C 退出...")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// 5. 循环读取并处理数据包
	for packet := range packetSource.Packets() {
		// 解析 UDP 层
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			
			// 识别并打印 IPv4 DHCP 报文
			if udp.SrcPort == 67 || udp.DstPort == 67 {
				fmt.Println("\n[捕获到 IPv4 DHCP 报文]")
				fmt.Printf("源端口: %d -> 目的端口: %d\n", udp.SrcPort, udp.DstPort)
				fmt.Printf("载荷内容 (Hex): %x\n", udp.Payload)
			}
			
			// 识别并打印 IPv6 DHCPv6 报文
			if udp.SrcPort == 547 || udp.DstPort == 547 {
				fmt.Println("\n[捕获到 IPv6 DHCPv6 报文]")
				if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
					ipv6, _ := ipv6Layer.(*layers.IPv6)
					fmt.Printf("源 IPv6: %s -> 目的 IPv6: %s\n", ipv6.SrcIP, ipv6.DstIP)
				}
				fmt.Printf("载荷内容 (Hex): %x\n", udp.Payload)
			}
		}
	}
}
