package v2ray

import (
	"fmt"
	"github.com/v2rayA/v2rayA/conf"
	"github.com/v2rayA/v2rayA/core/nftables"
	"github.com/v2rayA/v2rayA/core/specialMode"
	"github.com/v2rayA/v2rayA/db/configure"
	"github.com/v2rayA/v2rayA/pkg/util/log"
	"strings"
	"time"
)

func deleteTransparentProxyRules() {
	nftables.CloseWatcher()
	if !conf.GetEnvironmentConfig().Lite {
		removeResolvHijacker()
		nftables.Tproxy.GetCleanCommands().Run(false)
		nftables.Redirect.GetCleanCommands().Run(false)
		// nftables.DropSpoofing.GetCleanCommands().Run(false)
	}
	nftables.SystemProxy.GetCleanCommands().Run(false)
	time.Sleep(30 * time.Millisecond)
}

func writeTransparentProxyRules() (err error) {
	defer func() {
		if err != nil {
			log.Warn("writeTransparentProxyRules: %v", err)
			deleteTransparentProxyRules()
		}
	}()
	// if specialMode.ShouldUseSupervisor() {
	// 	if err = nftables.DropSpoofing.GetSetupCommands().Run(true); err != nil {
	// 		log.Warn("DropSpoofing can't be enable: %v", err)
	// 		return err
	// 	}
	// }
	setting := configure.GetSettingNotNil()
	switch setting.TransparentType {
	case configure.TransparentTproxy:
		if err = nftables.Tproxy.GetSetupCommands().Run(true); err != nil {
			if strings.Contains(err.Error(), "TPROXY") && strings.Contains(err.Error(), "No chain") {
				err = fmt.Errorf("you does not compile xt_TPROXY in kernel")
			}
			return fmt.Errorf("not support \"tproxy\" mode of transparent proxy: %w", err)
		}
		nftables.SetWatcher(&nftables.Tproxy)
	case configure.TransparentRedirect:
		if err = nftables.Redirect.GetSetupCommands().Run(true); err != nil {
			return fmt.Errorf("not support \"redirect\" mode of transparent proxy: %w", err)
		}
		nftables.SetWatcher(&nftables.Redirect)
	case configure.TransparentSystemProxy:
		if err = nftables.SystemProxy.GetSetupCommands().Run(true); err != nil {
			return fmt.Errorf("not support \"system proxy\" mode of transparent proxy: %w", err)
		}
	default:
		return fmt.Errorf("undefined \"%v\" mode of transparent proxy", setting.TransparentType)
	}

	if specialMode.ShouldLocalDnsListen() {
		if couldListenLocalhost, e := specialMode.CouldLocalDnsListen(); couldListenLocalhost {
			if e != nil {
				log.Warn("only listen at 127.2.0.17: %v", e)
			}
			resetResolvHijacker()
		} else if specialMode.ShouldUseFakeDns() {
			return fmt.Errorf("fakedns cannot be enabled: %w", e)
		} else {
			log.Warn("writeTransparentProxyRules: %v", e)
		}
	}
	return nil
}

func IsTransparentOn() bool {
	setting := configure.GetSettingNotNil()
	if setting.Transparent == configure.TransparentClose {
		return false
	}
	if conf.GetEnvironmentConfig().Lite &&
		(setting.TransparentType == configure.TransparentTproxy ||
			setting.TransparentType == configure.TransparentRedirect) {
		return false
	}
	return true
}
