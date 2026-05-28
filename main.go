package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// bytesToIPv6 将 16 字节切片转换为 net.IP（替代不存在的 net.IPv6Address）
func bytesToIPv6(b []byte) net.IP {
	if len(b) != 16 {
		return nil
	}
	ip := make(net.IP, 16)
	copy(ip, b)
	return ip
}

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal("获取网卡列表失败:", err)
	}

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

	fmt.Print("请输入要抓包的网卡编号: ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	selection, err := strconv.Atoi(input)
	if err != nil || selection < 1 || selection > len(devices) {
		log.Fatal("无效的网卡编号！")
	}

	selectedDevice := devices[selection-1]
	fmt.Printf("\n已选择网卡: %s (%s)\n\n", selectedDevice.Name, selectedDevice.Description)

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

	err = handle.SetBPFFilter("udp and (port 67 or port 68 or port 546 or port 547)")
	if err != nil {
		log.Fatal("设置过滤器失败:", err)
	}

	fmt.Println("[*] 开始监听 DHCP / DHCPv6 流量...")
	fmt.Println("提示：你可以打开新的终端执行 'ipconfig /renew' 或 'ipconfig /renew6' 来触发报文。")
	fmt.Println("按 Ctrl+C 退出监听。\n")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}
		udp, _ := udpLayer.(*layers.UDP)

		// ================= 处理 IPv4 DHCP 报文 =================
		if udp.SrcPort == 67 || udp.DstPort == 67 {
			dhcp := &layers.DHCPv4{}
			if err := dhcp.DecodeFromBytes(udp.Payload, gopacket.NilDecodeFeedback); err != nil {
				continue
			}

			var msgType layers.DHCPMsgType
			for _, opt := range dhcp.Options {
				if opt.Type == layers.DHCPOptMessageType {
					msgType = layers.DHCPMsgType(opt.Data[0])
					break
				}
			}

			if msgType == layers.DHCPMsgTypeAck {
				fmt.Println("\n[捕获到 IPv4 DHCP ACK 报文 - 配置下发]")
				fmt.Printf("下发 IP (YourClientIP): %s\n", dhcp.YourClientIP)
				fmt.Printf("DHCP 服务器 (NextServerIP): %s\n", dhcp.NextServerIP)

				for _, opt := range dhcp.Options {
					switch opt.Type {
					case layers.DHCPOptSubnetMask:
						if len(opt.Data) >= 4 {
							fmt.Printf("子网掩码: %s\n", net.IPv4(opt.Data[0], opt.Data[1], opt.Data[2], opt.Data[3]))
						}
					case layers.DHCPOptRouter:
						if len(opt.Data) >= 4 {
							fmt.Printf("默认网关: %s\n", net.IPv4(opt.Data[0], opt.Data[1], opt.Data[2], opt.Data[3]))
						}
					case layers.DHCPOptDNS:
						if len(opt.Data) >= 4 {
							fmt.Printf("DNS 服务器: %s\n", net.IPv4(opt.Data[0], opt.Data[1], opt.Data[2], opt.Data[3]))
						}
					case layers.DHCPOptDomainName:
						fmt.Printf("域名: %s\n", string(opt.Data))
					case layers.DHCPOptBroadcastAddr:
						if len(opt.Data) >= 4 {
							fmt.Printf("广播地址: %s\n", net.IPv4(opt.Data[0], opt.Data[1], opt.Data[2], opt.Data[3]))
						}
					case layers.DHCPOptLeaseTime:
						if len(opt.Data) == 4 {
							fmt.Printf("IP 租约时间: %d 秒\n", binary.BigEndian.Uint32(opt.Data))
						}
					case layers.DHCPOptServerID: // ✅ v1.1.19 中 Option 54 的正确常量名
						if len(opt.Data) >= 4 {
							fmt.Printf("DHCP 服务器标识符 (Option 54): %s\n", net.IPv4(opt.Data[0], opt.Data[1], opt.Data[2], opt.Data[3]))
						}
					default:
						fmt.Printf("选项 %d (Hex): %x\n", opt.Type, opt.Data)
					}
				}
			} else {
				fmt.Printf("\n[IPv4 DHCP 交互] 类型: %v, 客户端MAC: %s\n", msgType, dhcp.ClientHWAddr)
			}
		}

		// ================= 处理 IPv6 DHCPv6 报文 =================
		if udp.SrcPort == 547 || udp.DstPort == 547 {
			dhcpv6 := &layers.DHCPv6{}
			if err := dhcpv6.DecodeFromBytes(udp.Payload, gopacket.NilDecodeFeedback); err != nil {
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
				switch opt.Code {
				// ✅ 以下所有常量均严格来自你提供的 v1.1.19 定义
				case layers.DHCPv6OptServerID: // Code 2
					if len(opt.Data) == 16 {
						fmt.Printf("  ServerID (IPv6): %s\n", bytesToIPv6(opt.Data))
					} else {
						fmt.Printf("  ServerID (DUID, Hex): %x\n", opt.Data)
					}
				case layers.DHCPv6OptClientID: // Code 1
					if len(opt.Data) >= 14 && opt.Data[0] == 1 { // DUID-LLT
						fmt.Printf("  ClientID (DUID-LLT, MAC): %s\n", net.HardwareAddr(opt.Data[8:14]))
					} else if len(opt.Data) >= 10 && opt.Data[0] == 3 { // DUID-LL
						fmt.Printf("  ClientID (DUID-LL, MAC): %s\n", net.HardwareAddr(opt.Data[6:12]))
					} else {
						fmt.Printf("  ClientID (Hex): %x\n", opt.Data)
					}
				case layers.DHCPv6OptIANA: // Code 3 (替代之前错误的 IA_NA)
					if len(opt.Data) >= 4 {
						fmt.Printf("  IA_NA (IAID): %x\n", opt.Data[0:4])
					} else {
						fmt.Printf("  IA_NA (Hex): %x\n", opt.Data)
					}
				case layers.DHCPv6OptIATA: // Code 4 (替代之前错误的 IA_TA)
					if len(opt.Data) >= 4 {
						fmt.Printf("  IA_TA (IAID): %x\n", opt.Data[0:4])
					} else {
						fmt.Printf("  IA_TA (Hex): %x\n", opt.Data)
					}
				case layers.DHCPv6OptIAPD: // Code 25 (替代之前错误的 IA_PD)
					if len(opt.Data) >= 4 {
						fmt.Printf("  IA_PD (IAID): %x\n", opt.Data[0:4])
					} else {
						fmt.Printf("  IA_PD (Hex): %x\n", opt.Data)
					}
				case layers.DHCPv6OptDNSServers: // Code 23 (替代之前错误的 DNSServers)
					if len(opt.Data)%16 == 0 && len(opt.Data) > 0 {
						fmt.Print("  DNS Servers:")
						for i := 0; i < len(opt.Data); i += 16 {
							fmt.Printf(" %s", bytesToIPv6(opt.Data[i:i+16]))
						}
						fmt.Println()
					} else {
						fmt.Printf("  DNS Servers (Hex): %x\n", opt.Data)
					}
				case layers.DHCPv6OptDomainList: // Code 24 (替代之前错误的 DomainSearchList)
					fmt.Printf("  Domain Search List: %s\n", string(opt.Data))
				default:
					fmt.Printf("  Option %d (Length=%d, Hex): %x\n", opt.Code, opt.Length, opt.Data)
				}
			}
		}
	}
}
