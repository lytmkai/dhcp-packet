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

// ================= 全局常量与辅助函数 =================

// RA 报文中的选项类型常量
const (
	RAOptSourceLinkLayerAddr = 1  // 源链路层地址 (MAC)
	RAOptPrefixInformation   = 3  // 前缀信息
	RAOptMTU                 = 5  // 链路 MTU
	RAOptRDNSS               = 25 // 递归 DNS 服务器 (RFC 6106)

	optTypeSrcLinkAddr byte = 1   // 源链路层地址选项
	optTypePrefixInfo  byte = 3   // 前缀信息选项
	optTypeMTU         byte = 5   // MTU 选项
	optTypeRDNSS       byte = 25  // RDNSS (DNS) 选项
)

// bytesToIPv6 将 16 字节切片转换为 net.IP
func bytesToIPv6(b []byte) net.IP {
	if len(b) != 16 {
		return nil
	}
	ip := make(net.IP, 16)
	copy(ip, b)
	return ip
}

// ================= 主函数 =================

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
	)

	handle, err := pcap.OpenLive(selectedDevice.Name, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal("打开网卡失败:", err)
	}
	defer handle.Close()

	// 注意：此处不使用 BPF 过滤器，以便同时捕获 UDP(DHCP) 和 ICMPv6(RA)
	fmt.Println("[*] 开始监听 DHCP / DHCPv6 / RA (ICMPv6 Type 134) 流量...")
	fmt.Println("提示：触发 IP 获取或等待路由器广播。按 Ctrl+C 退出监听。\n")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// 尝试解析 UDP (用于 DHCP)
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			handleDHCP(packet, udpLayer.(*layers.UDP))
			continue
		}

		// 尝试解析 ICMPv6 (用于 RA)
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv6); icmpLayer != nil {
			handleRA(packet, icmpLayer.(*layers.ICMPv6))
			continue
		}
	}
}

// ================= DHCP 处理逻辑 =================

func handleDHCP(packet gopacket.Packet, udp *layers.UDP) {
	// ---------- IPv4 DHCP ----------
	if (udp.SrcPort == 67 || udp.DstPort == 67) && udp.SrcPort != 547 && udp.DstPort != 547 {
		dhcp := &layers.DHCPv4{}
		if err := dhcp.DecodeFromBytes(udp.Payload, gopacket.NilDecodeFeedback); err != nil {
			return
		}

		var msgType layers.DHCPMsgType
		for _, opt := range dhcp.Options {
			if opt.Type == layers.DHCPOptMessageType {
				msgType = layers.DHCPMsgType(opt.Data[0])
				break
			}
		}

		if msgType == layers.DHCPMsgTypeAck {
			fmt.Printf("\n[%s 捕获到 IPv4 DHCP ACK 报文 - 配置下发]\n", time.Now().Format("15:04:05"))
			fmt.Printf("  下发 IP (YourClientIP): %s\n", dhcp.YourClientIP)
			fmt.Printf("  DHCP 服务器 (NextServerIP): %s\n", dhcp.NextServerIP)

			for _, opt := range dhcp.Options {
				switch opt.Type {
				case layers.DHCPOptSubnetMask:
					if len(opt.Data) >= 4 {
						fmt.Printf("  子网掩码: %s\n", net.IPv4(opt.Data[0], opt.Data[1], opt.Data[2], opt.Data[3]))
					}
				case layers.DHCPOptRouter:
					if len(opt.Data) >= 4 {
						fmt.Printf("  默认网关: %s\n", net.IPv4(opt.Data[0], opt.Data[1], opt.Data[2], opt.Data[3]))
					}
				case layers.DHCPOptDNS:
					if len(opt.Data) >= 4 {
						fmt.Printf("  DNS 服务器: %s\n", net.IPv4(opt.Data[0], opt.Data[1], opt.Data[2], opt.Data[3]))
					}
				case layers.DHCPOptDomainName:
					fmt.Printf("  域名: %s\n", string(opt.Data))
				case layers.DHCPOptLeaseTime:
					if len(opt.Data) == 4 {
						fmt.Printf("  IP 租约时间: %d 秒\n", binary.BigEndian.Uint32(opt.Data))
					}
				case layers.DHCPOptServerID:
					if len(opt.Data) >= 4 {
						fmt.Printf("  DHCP 服务器标识符: %s\n", net.IPv4(opt.Data[0], opt.Data[1], opt.Data[2], opt.Data[3]))
					}
				}
			}
		} else if udp.SrcPort == 67 || udp.DstPort == 68 {
			fmt.Printf("[IPv4 DHCP] %v 交互\n", msgType)
		}
		return
	}

	// ---------- IPv6 DHCPv6 ----------
	if udp.SrcPort == 547 || udp.DstPort == 547 {
		dhcpv6 := &layers.DHCPv6{}
		if err := dhcpv6.DecodeFromBytes(udp.Payload, gopacket.NilDecodeFeedback); err != nil {
			return
		}

		fmt.Printf("\n[%s 捕获到 IPv6 DHCPv6 报文]\n", time.Now().Format("15:04:05"))
		fmt.Printf("  报文类型: %v\n", dhcpv6.MsgType)

		if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
			ipv6 := ipv6Layer.(*layers.IPv6)
			fmt.Printf("  源: %s -> 目的: %s\n", ipv6.SrcIP, ipv6.DstIP)
		}

		for _, opt := range dhcpv6.Options {
			switch opt.Code {
			case layers.DHCPv6OptServerID:
				fmt.Printf("  ServerID: %x\n", opt.Data)
			case layers.DHCPv6OptClientID:
				fmt.Printf("  ClientID: %x\n", opt.Data)
			case layers.DHCPv6OptIANA:
				fmt.Printf("  IA_NA: %x\n", opt.Data)
			case layers.DHCPv6OptIATA:
				fmt.Printf("  IA_TA: %x\n", opt.Data)
			case layers.DHCPv6OptIAPD:
				fmt.Printf("  IA_PD: %x\n", opt.Data)
			case layers.DHCPv6OptDNSServers:
				if len(opt.Data)%16 == 0 {
					fmt.Print("  DNS Servers:")
					for i := 0; i < len(opt.Data); i += 16 {
						fmt.Printf(" %s", bytesToIPv6(opt.Data[i:i+16]))
					}
					fmt.Println()
				}
			case layers.DHCPv6OptDomainList:
				fmt.Printf("  Domain Search: %s\n", string(opt.Data))
			}
		}
	}
}

// ================= RA 处理逻辑 =================
func handleRA(packet gopacket.Packet, icmp *layers.ICMPv6) {
	// 仅处理 Router Advertisement (Type 134)
	if icmp.TypeCode.Type() != 134 {
		return
	}

	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer == nil {
		return
	}
	ipv6 := ipv6Layer.(*layers.IPv6)

	fmt.Printf("\n[%s 捕获到 RA 报文] 源 IPv6: %s\n", time.Now().Format("15:04:05"), ipv6.SrcIP)

	// icmp.Payload = RA 固定字段(12B) + Options
	// 结构: [HopLimit(1)][Flags(1)][RouterLifetime(2)][ReachableTime(4)][RetransTimer(4)] = 12 bytes
	payload := icmp.Payload
	if len(payload) < 12 {
		fmt.Println("  [信息] RA 数据过短，无法解析")
		fmt.Println("---")
		return
	}

	// 解析 RA 固定字段
	hopLimit := payload[0]
	flags := payload[1]
	routerLifetime := binary.BigEndian.Uint16(payload[2:4])
	reachableTime := binary.BigEndian.Uint32(payload[4:8])
	retransTimer := binary.BigEndian.Uint32(payload[8:12])

	fmt.Printf("  [RA头部] 跳数限制: %d, 标志位: 0x%02X (M=%d, O=%d), 路由器生存期: %d秒\n",
		hopLimit, flags, (flags>>7)&1, (flags>>6)&1, routerLifetime)
	fmt.Printf("  [RA头部] 可达时间: %d ms, 重传定时器: %d ms\n", reachableTime, retransTimer)

	// Options 从 payload[12:] 开始
	optionsData := payload[12:]
	if len(optionsData) == 0 {
		fmt.Println("  [信息] 无 RA Options")
	} else {
		parseRAOptions(optionsData)
	}
	fmt.Println("---")
}

func parseRAOptions(icmpPayload []byte) {
	// 这里的 icmpPayload 是传进来的，也就是跳过了 RA 固定头(12字节)之后的纯 Options 数据
	optionsData := icmpPayload
	i := 0

	for i+2 <= len(optionsData) {
		// 1. 提取当前 Option 的类型和长度
		optType := optionsData[i]
		optLen := int(optionsData[i+1]) * 8 // 长度单位是 8 字节

		// 防御性检查：防止长度异常导致 panic
		if optLen == 0 || i+optLen > len(optionsData) {
			break 
		}

		// 截取当前整个 Option 的二进制数据
		optData := optionsData[i : i+optLen]

		switch optType {
		// ================= 前缀信息选项 (Type 3) =================
		case optTypePrefixInfo:
			// 必须保证至少有 30 个字节 (2字节头 + 14字节属性 + 16字节前缀)
			if len(optData) >= 30 { 
				prefixLen := optData[2] // 前缀长度 (例如 64)
				
				// 16 字节的 IPv6 前缀从索引 16 开始
				prefixIP := net.IP(optData[16:32])
				fmt.Printf("  [前缀] 推荐前缀: %s/%d\n", prefixIP.String(), prefixLen)
			}

		// ================= 链路 MTU 选项 (Type 5) =================
		case optTypeMTU:
			if len(optData) >= 8 {
				// MTU 值从 Option 内部的第 4 字节开始
				mtu := binary.BigEndian.Uint32(optData[4:8])
				fmt.Printf("  [MTU] 链路 MTU: %d\n", mtu)
			}

		// ================= DNS 服务器选项 (Type 25) =================
		case optTypeRDNSS:
			if len(optData) >= 6 {
				// 生存期从 Option 内部的第 2 字节开始
				lifetime := binary.BigEndian.Uint32(optData[2:6])
				fmt.Printf("  [DNS] RDNSS Lifetime: %d 秒\n", lifetime)
			}

		// ================= 源链路层地址选项 (Type 1) =================
		case optTypeSrcLinkAddr:
			if len(optData) >= 8 {
				mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
					optData[2], optData[3], optData[4], optData[5], optData[6], optData[7])
				fmt.Printf("  [MAC 地址] 源链路层地址: %s\n", mac)
			}
		}

		// 指针移动到下一个 Option
		i += optLen
	}
}
