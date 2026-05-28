package main

import (
	"bufio"
	"encoding/binary"
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
		snapshotLen int32         = 65535
		promiscuous bool          = true
		timeout     time.Duration = 30 * time.Second
		handle      *pcap.Handle
	)

	handle, err = pcap.OpenLive(selectedDevice.Name, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal("打开网卡失败:", err)
	}
	defer handle.Close()

	// 设置 BPF 过滤器
	err = handle.SetBPFFilter("udp and (port 67 or port 68 or port 546 or port 547)")
	if err != nil {
		log.Fatal("设置过滤器失败:", err)
	}

	fmt.Println("[*] 开始监听 DHCP / DHCPv6 流量...")
	fmt.Println("提示：你可以打开新的终端执行 'ipconfig /renew' 或 'ipconfig /renew6' 来触发报文。")
	fmt.Println("按 Ctrl+C 退出监听。\n")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// 5. 循环读取并处理数据包
	for packet := range packetSource.Packets() {
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}
		udp, _ := udpLayer.(*layers.UDP)

		// ================= 处理 IPv4 DHCP 报文 =================
		if udp.SrcPort == 67 || udp.DstPort == 67 {
			dhcp := &layers.DHCPv4{}
			err := dhcp.DecodeFromBytes(udp.Payload, gopacket.NilDecodeFeedback)
			if err != nil {
				continue
			}

			// 获取 DHCP 报文类型 (通过 Option 53)
			var msgType layers.DHCPMsgType
			for _, opt := range dhcp.Options {
				if opt.Type == layers.DHCPOptionMessageType {
					msgType = layers.DHCPMsgType(opt.Data[0])
					break
				}
			}

			// 优先展示服务器下发的 ACK 包
			if msgType == layers.DHCPMsgTypeAck {
				fmt.Println("\n[捕获到 IPv4 DHCP ACK 报文 - 配置下发]")
				fmt.Printf("下发 IP (YourIP): %s\n", dhcp.YourClientIP)
				// 修复：ServerIP 字段在新版本中通常为 ServerIPAddress
				fmt.Printf("DHCP 服务器 (ServerIP): %s\n", dhcp.ServerIPAddress)

				for _, opt := range dhcp.Options {
					switch opt.Type {
					case layers.DHCPOptionSubnetMask:
						fmt.Printf("子网掩码: %s\n", opt.Data)
					case layers.DHCPOptionRouter:
						fmt.Printf("默认网关: %s\n", opt.Data)
					// 修复：常量名称适配
					case layers.DHCPOptionDomainNameServer:
						fmt.Printf("DNS 服务器: %s\n", opt.Data)
					case layers.DHCPOptionDomainName:
						fmt.Printf("域名: %s\n", string(opt.Data))
					case layers.DHCPOptionBroadcastAddress:
						fmt.Printf("广播地址: %s\n", opt.Data)
					// 修复：常量名称适配
					case layers.DHCPOptionIPAddressLeaseTime:
						if len(opt.Data) == 4 {
							seconds := binary.BigEndian.Uint32(opt.Data)
							fmt.Printf("IP 租约时间: %d 秒\n", seconds)
						}
					}
				}
			} else {
				fmt.Printf("\n[IPv4 DHCP 交互] 类型: %v, 客户端MAC: %s\n", msgType, dhcp.ClientHWAddr)
			}
		}

		// ================= 处理 IPv6 DHCPv6 报文 =================
		if udp.SrcPort == 547 || udp.DstPort == 547 {
			dhcpv6 := &layers.DHCPv6{}
			err := dhcpv6.DecodeFromBytes(udp.Payload, gopacket.NilDecodeFeedback)
			if err != nil {
				continue
			}

			fmt.Println("\n[捕获到 IPv6 DHCPv6 报文]")
			fmt.Printf("报文类型 (MsgType): %v\n", dhcpv6.MsgType)
			fmt.Printf("事务ID (TransactionID): %x\n", dhcpv6.TransactionID)

			if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
				ipv6, _ := ipv6Layer.(*layers.IPv6)
				fmt.Printf("源 IPv6: %s -> 目的 IPv6: %s\n", ipv6.SrcIP, ipv6.DstIP)
			}

			fmt.Println("--- DHCPv6 下发的 Option 信息 ---")
			for _, opt := range dhcpv6.Options {
				// 修复：DHCPv6Option 的字段名是 Code 而不是 Type
				fmt.Printf("  选项代码(Code): %v | 长度: %d | 原始数据(Hex): %x\n", opt.Code, opt.Length, opt.Data)
			}
		}
	}
}
