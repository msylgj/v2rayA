package nftables

import (
	"fmt"
	"github.com/v2rayA/v2rayA/common/cmds"
	"github.com/v2rayA/v2rayA/db/configure"
	"strings"
)

type tproxy struct {
	watcher *LocalIPWatcher
}

var Tproxy tproxy

func (t *tproxy) AddIPWhitelist(cidr string) {
	// avoid duplication
	t.RemoveIPWhitelist(cidr)
	pos := 6
	if configure.GetSettingNotNil().AntiPollution != configure.AntipollutionClosed {
		pos += 3
	}

	var commands string
	commands = fmt.Sprintf(`nft add rule inet fw4 TP_MANGLE_RULE index %v ip daddr %s RETURN`, pos, cidr)
	if !strings.Contains(cidr, ".") {
		//ipv6
		commands = strings.Replace(commands, "ip", "ip6", 1)
	}
	cmds.ExecCommands(commands, false)
}

func (t *tproxy) RemoveIPWhitelist(cidr string) {
	var commands string
	handles, err := GetHandles("chain inet fw4 TP_MANGLE_RULE", cidr)
	if err != nil {
		return
	}
	for _, handle :=range handles{
		commands += fmt.Sprintf(`nft delete rule inet fw4 TP_MANGLE_RULE handle %s\n`, handle)
	}
	cmds.ExecCommands(commands, false)
}

func (t *tproxy) GetSetupCommands() Setter {
	commands := `
ip rule add fwmark 0x40/0xc0 table 100
ip route add local 0.0.0.0/0 dev lo table 100

nft add chain inet fw4 TP_MANGLE_OUT
nft add chain inet fw4 TP_MANGLE_PRE
nft add chain inet fw4 TP_MANGLE_RULE
nft add chain inet fw4 TP_MARK

nft insert rule inet fw4 mangle_output meta l4proto { tcp, udp } counter jump TP_MANGLE_OUT
nft insert rule inet fw4 mangle_prerouting meta l4proto { tcp, udp } counter jump TP_MANGLE_PRE

nft add rule inet fw4 TP_MANGLE_OUT meta mark & 0x80 == 0x80 RETURN
nft add rule inet fw4 TP_MANGLE_OUT meta l4proto { tcp, udp } fib saddr type == { LOCAL } fib daddr type != { LOCAL } jump TP_MANGLE_RULE

nft add rule inet fw4 TP_MANGLE_PRE iifname "lo" meta mark & 0xc0 != 0x40 RETURN
nft add rule inet fw4 TP_MANGLE_PRE meta l4proto { tcp, udp } fib saddr type != { LOCAL } fib daddr type != { LOCAL } jump TP_MANGLE_RULE
nft add rule inet fw4 TP_MANGLE_PRE meta nfproto {ipv4} tcp meta mark & 0xc0 != 0x40 tproxy ip to 127.0.0.1:32345 counter accept
nft add rule inet fw4 TP_MANGLE_PRE meta nfproto {ipv4} upd meta mark & 0xc0 != 0x40 tproxy ip to 127.0.0.1:32345 counter accept

nft add rule inet fw4 TP_MANGLE_RULE meta mark set ct mark
nft add rule inet fw4 TP_MANGLE_RULE meta mark & 0xc0 != 0x40 RETURN
nft add rule inet fw4 TP_MANGLE_RULE iifname "br-*" RETURN
nft add rule inet fw4 TP_MANGLE_RULE iifname "docker*" RETURN
nft add rule inet fw4 TP_MANGLE_RULE iifname "veth*" RETURN
nft add rule inet fw4 TP_MANGLE_RULE iifname "ppp*" RETURN
nft add rule inet fw4 TP_MANGLE_RULE iifname "dn42-*" RETURN
`
	if configure.GetSettingNotNil().AntiPollution != configure.AntipollutionClosed {
		commands += `
nft add rule inet fw4 TP_MANGLE_RULE meta l4proto { tcp, udp } dport 53 jump TP_MARK
nft add rule inet fw4 TP_MANGLE_RULE meta mark & 0xc0 != 0x40 RETURN
`
	}
	commands += `
nft add rule inet fw4 TP_MANGLE_RULE ip daddr 0.0.0.0/32 RETURN
nft add rule inet fw4 TP_MANGLE_RULE ip daddr 10.0.0.0/8 RETURN
nft add rule inet fw4 TP_MANGLE_RULE ip daddr 100.64.0.0/10 RETURN
nft add rule inet fw4 TP_MANGLE_RULE ip daddr 127.0.0.0/8 RETURN
nft add rule inet fw4 TP_MANGLE_RULE ip daddr 169.254.0.0/16 RETURN
nft add rule inet fw4 TP_MANGLE_RULE ip daddr 172.16.0.0/12 RETURN
nft add rule inet fw4 TP_MANGLE_RULE ip daddr 192.0.0.0/24 RETURN
nft add rule inet fw4 TP_MANGLE_RULE ip daddr 192.0.2.0/24 RETURN
nft add rule inet fw4 TP_MANGLE_RULE ip daddr 192.88.99.0/24 RETURN
nft add rule inet fw4 TP_MANGLE_RULE ip daddr 192.168.0.0/16 RETURN
# fakedns
# nft add rule inet fw4 TP_MANGLE_RULE ip daddr 198.18.0.0/15 -j RETURN
nft add rule inet fw4 TP_MANGLE_RULE ip daddr 198.51.100.0/24 -j RETURN
nft add rule inet fw4 TP_MANGLE_RULE ip daddr 203.0.113.0/24 -j RETURN
nft add rule inet fw4 TP_MANGLE_RULE ip daddr 224.0.0.0/4 -j RETURN
nft add rule inet fw4 TP_MANGLE_RULE ip daddr 240.0.0.0/4 -j RETURN
nft add rule inet fw4 TP_MANGLE_RULE jump TP_MARK

nft add rule inet fw4 TP_MARK meta l4proto tcp flags syn meta mark set mark | 0x40
nft add rule inet fw4 TP_MARK meta l4proto udp ct state NEW meta mark set mark | 0x40
nft add rule inet fw4 TP_MARK ct mark set mark
`
	if IsIPv6Supported() {
		commands += `
ip -6 rule add fwmark 0x40/0xc0 table 100
ip -6 route add local ::/0 dev lo table 100

nft add rule inet fw4 TP_MANGLE_PRE meta meta nfproto {ipv6} tcp meta mark & 0xc0 != 0x40 tproxy ip6 to :32345 counter accept
nft add rule inet fw4 TP_MANGLE_PRE meta meta nfproto {ipv6} upd meta mark & 0xc0 != 0x40 tproxy ip6 to :32345 counter accept

nft insert rule inet fw4 TP_MANGLE_RULE ip6 daddr ::/128 -j RETURN
nft insert rule inet fw4 TP_MANGLE_RULE ip6 daddr ::1/128 -j RETURN
nft insert rule inet fw4 TP_MANGLE_RULE ip6 daddr 64:ff9b::/96 -j RETURN
nft insert rule inet fw4 TP_MANGLE_RULE ip6 daddr 100::/64 -j RETURN
nft insert rule inet fw4 TP_MANGLE_RULE ip6 daddr 2001::/32 -j RETURN
nft insert rule inet fw4 TP_MANGLE_RULE ip6 daddr 2001:20::/28 -j RETURN
nft insert rule inet fw4 TP_MANGLE_RULE ip6 daddr fe80::/10 -j RETURN
nft insert rule inet fw4 TP_MANGLE_RULE ip6 daddr ff00::/8 -j RETURN
`
	}
	return Setter{
		Cmds:      commands,
	}
}

func (t *tproxy) GetCleanCommands() Setter {
	commands := `
ip rule del fwmark 0x40/0xc0 table 100
ip route del local 0.0.0.0/0 dev lo table 100

nft flush chain inet fw4 TP_MANGLE_OUT
`
	handles, err := GetHandles("chain inet fw4 mangle_output", "TP_MANGLE_OUT")
	if err == nil {
		for _, handle :=range handles{
			commands += fmt.Sprintf(`nft delete rule inet fw4 mangle_output handle %s\n`, handle)
		}
	}
	commands += `
nft delete chain inet fw4 TP_MANGLE_OUT
nft flush chain inet fw4 TP_MANGLE_PRE
`
	handles, err = GetHandles("chain inet fw4 mangle_prerouting", "TP_MANGLE_PRE")
	if err != nil {
		for _, handle :=range handles{
			commands += fmt.Sprintf(`nft delete rule inet fw4 mangle_prerouting handle %s\n`, handle)
		}
	}
	commands += `
nft delete chain inet fw4 TP_MANGLE_PRE
nft flush chain inet fw4 TP_MANGLE_RULE
nft delete chain inet fw4 TP_MANGLE_RULE
nft flush chain inet fw4 TP_MARK
nft delete chain inet fw4 TP_MARK
`
	if IsIPv6Supported() {
		commands += `
ip -6 rule del fwmark 0x40/0xc0 table 100
ip -6 route del local ::/0 dev lo table 100
`
	}
	return Setter{
		Cmds:      commands,
	}
}
