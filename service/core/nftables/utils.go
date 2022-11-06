package nftables

import (
	"fmt"
	"github.com/v2rayA/v2rayA/common"
	"github.com/v2rayA/v2rayA/common/cmds"
	"github.com/v2rayA/v2rayA/conf"
	"golang.org/x/net/nettest"
	"net"
	"os/exec"
	"strconv"
)

func IPNet2CIDR(ipnet *net.IPNet) string {
	ones, _ := ipnet.Mask.Size()
	return ipnet.IP.String() + "/" + strconv.Itoa(ones)
}

func GetLocalCIDR() ([]string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var cidrs []string
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			cidrs = append(cidrs, IPNet2CIDR(ipnet))
		}
	}
	return cidrs, nil
}

func IsIPv6Supported() bool {
	switch conf.GetEnvironmentConfig().IPV6Support {
	case "on":
		return true
	case "off":
		return false
	default:
	}
	if common.IsDocker() {
		return false
	}
	if !nettest.SupportsIPv6() {
		return false
	}
	return cmds.IsCommandValid("ip6tables")
}

func GetHandles(eleType string, keyword string) ([]string, error) {
	line := fmt.Sprintf(`nft -a list %s |grep -E "%s" |awk -F '# handle ' '{print$2}'`, eleType, keyword)
	out, err := exec.Command("sh", "-c", line).CombinedOutput()
	if err != nil {
		return nil, err
	}
	var handles []string
	for _, handle := range out {
		if len(handle) <= 0 {
			continue
		}
		handles = append(handles, handle)
	}
	return handles, nil
}
