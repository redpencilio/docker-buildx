package plugin

import (
	"fmt"
	"os"
)

func (p *Plugin) applyProxyConf() error {
	if p.settings.ProxyConf.Http == "" &&
		p.settings.ProxyConf.Https == "" &&
		p.settings.ProxyConf.No == "" {
		return nil
	}

	// we set the environment for all commands we do exec
	if p.settings.ProxyConf.Http != "" {
		if err := os.Setenv("HTTP_PROXY", p.settings.ProxyConf.Http); err != nil {
			return fmt.Errorf("could not set HTTP_PROXY as environment variable: %w", err)
		}
	}
	if p.settings.ProxyConf.Https != "" {
		if err := os.Setenv("HTTPS_PROXY", p.settings.ProxyConf.Https); err != nil {
			return fmt.Errorf("could not set HTTPS_PROXY as environment variable: %w", err)
		}
	}
	if p.settings.ProxyConf.No != "" {
		if err := os.Setenv("NO_PROXY", p.settings.ProxyConf.No); err != nil {
			return fmt.Errorf("could not set NO_PROXY as environment variable: %w", err)
		}
	}

	// add driver-opt http config to tell buildkit + buildx to resolve external checksums through a proxy.
	if p.settings.ProxyConf.Http != "" {
		p.settings.Daemon.BuildkitDriverOpt = append(p.settings.Daemon.BuildkitDriverOpt, fmt.Sprintf("env.http_proxy=%s", p.settings.ProxyConf.Http))
	}
	if p.settings.ProxyConf.Https != "" {
		p.settings.Daemon.BuildkitDriverOpt = append(p.settings.Daemon.BuildkitDriverOpt, fmt.Sprintf("env.https_proxy=%s", p.settings.ProxyConf.Https))
	}
	if p.settings.ProxyConf.No != "" {
		p.settings.Daemon.BuildkitDriverOpt = append(p.settings.Daemon.BuildkitDriverOpt, fmt.Sprintf("env.no_proxy=%s", p.settings.ProxyConf.No))
	}

	// passthrough proxy config to the build process and Dockerfile CMDs itself.
	if p.settings.ProxyConf.Http != "" {
		p.settings.Build.Args = append(p.settings.Build.Args, fmt.Sprintf("HTTP_PROXY=%s", p.settings.ProxyConf.Http))
	}
	if p.settings.ProxyConf.Https != "" {
		p.settings.Build.Args = append(p.settings.Build.Args, fmt.Sprintf("HTTPS_PROXY=%s", p.settings.ProxyConf.Https))
	}
	if p.settings.ProxyConf.No != "" {
		p.settings.Build.Args = append(p.settings.Build.Args, fmt.Sprintf("NO_PROXY=%s", p.settings.ProxyConf.No))
	}

	return nil
}
