package nftables

import (
	"fmt"
	"github.com/v2rayA/v2rayA/common/cmds"
	"strings"
)

type redirect struct{}

var Redirect redirect

func (r *redirect) AddIPWhitelist(cidr string) {
	// avoid duplication
	r.RemoveIPWhitelist(cidr)
	var commands string
	commands = fmt.Sprintf(`nft insert rule inet fw4 TP_RULE ip daddr %s return`, cidr)
	if !strings.Contains(cidr, ".") {
		//ipv6
		commands = strings.Replace(commands, "ip", "ip6", 1)
	}
	cmds.ExecCommands(commands, false)
}

func (r *redirect) RemoveIPWhitelist(cidr string) {
	var commands string
	handles, err := GetHandles("chain inet fw4 TP_RULE", cidr)
	if err != nil {
		return
	}
	for _, handle :=range handles{
		handle = strings.TrimSpace(handle)
		if len(handle) <= 0 {
			continue
		}
		commands += fmt.Sprintf("nft delete rule inet fw4 TP_RULE handle %s\n", handle)
	}
	cmds.ExecCommands(commands, false)
}

func (r *redirect) GetSetupCommands() Setter {
	commands := `
nft add chain inet fw4 TP_OUT
nft add chain inet fw4 TP_PRE
nft add chain inet fw4 TP_RULE
nft add chain inet fw4 nat_output { type nat hook output priority -1\; }
nft add rule inet fw4 TP_RULE ip daddr 0.0.0.0/32 return
nft add rule inet fw4 TP_RULE ip daddr 10.0.0.0/8 return
nft add rule inet fw4 TP_RULE ip daddr 100.64.0.0/10 return
nft add rule inet fw4 TP_RULE ip daddr 127.0.0.0/8 return
nft add rule inet fw4 TP_RULE ip daddr 169.254.0.0/16 return
nft add rule inet fw4 TP_RULE ip daddr 172.16.0.0/12 return
nft add rule inet fw4 TP_RULE ip daddr 192.0.0.0/24 return
nft add rule inet fw4 TP_RULE ip daddr 192.0.2.0/24 return
nft add rule inet fw4 TP_RULE ip daddr 192.88.99.0/24 return
nft add rule inet fw4 TP_RULE ip daddr 192.168.0.0/16 return
# fakedns
# nft add rule inet fw4 TP_RULE ip daddr 198.18.0.0/15 return
nft add rule inet fw4 TP_RULE ip daddr 198.51.100.0/24 return
nft add rule inet fw4 TP_RULE ip daddr 203.0.113.0/24 return
nft add rule inet fw4 TP_RULE ip daddr 224.0.0.0/4 return
nft add rule inet fw4 TP_RULE ip daddr 240.0.0.0/4 return
nft add rule inet fw4 TP_RULE meta mark \& 0x80 == 0x80 return
nft add rule inet fw4 TP_RULE meta l4proto tcp counter redirect to :32345

nft insert rule inet fw4 dstnat meta l4proto tcp counter jump TP_PRE
nft insert rule inet fw4 nat_output meta l4proto tcp counter jump TP_OUT
nft add rule inet fw4 TP_PRE jump TP_RULE
nft add rule inet fw4 TP_OUT jump TP_RULE
`
	if IsIPv6Supported() {
		commands += `
nft add rule inet fw4 TP_RULE ip6 daddr ::/128 return
nft add rule inet fw4 TP_RULE ip6 daddr ::1/128 return
nft add rule inet fw4 TP_RULE ip6 daddr 64:ff9b::/96 return
nft add rule inet fw4 TP_RULE ip6 daddr 100::/64 return
nft add rule inet fw4 TP_RULE ip6 daddr 2001::/32 return
nft add rule inet fw4 TP_RULE ip6 daddr 2001:20::/28 return
nft add rule inet fw4 TP_RULE ip6 daddr 2001:db8::/32 return
nft add rule inet fw4 TP_RULE ip6 daddr 2002::/16 return
# fakedns
# nft add rule inet fw4 TP_RULE ip6 daddr fc00::/7 return
nft add rule inet fw4 TP_RULE ip6 daddr fe80::/10 return
nft add rule inet fw4 TP_RULE ip6 daddr ff00::/8 return
`
	}
	return Setter{
		Cmds:      commands,
	}
}

func (r *redirect) GetCleanCommands() Setter {
	commands := `
nft flush chain inet fw4 nat_output
nft flush chain inet fw4 TP_OUT
nft delete chain inet fw4 TP_OUT
nft delete chain inet fw4 nat_output
nft flush chain inet fw4 TP_PRE
`
	handles, err := GetHandles("chain inet fw4 dstnat", "TP_PRE")
	if err == nil {
		for _, handle :=range handles{
			handle = strings.TrimSpace(handle)
			if len(handle) <= 0 {
				continue
			}
			commands += fmt.Sprintf("nft delete rule inet fw4 dstnat handle %s\n", handle)
		}
	}

	commands += `
nft delete chain inet fw4 TP_PRE
nft flush chain inet fw4 TP_RULE
nft delete chain inet fw4 TP_RULE
`
	return Setter{
		Cmds:      commands,
	}
}
