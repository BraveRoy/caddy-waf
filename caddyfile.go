package waf

import (
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"strconv"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("waf", parseCaddyfile)
}

// UnmarshalCaddyfile
func (w *CaddyWaf) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.NextArg()
	var err error
	for d.NextBlock(0) {
		switch d.Val() {
		case "args_rule":
			d.NextArg()
			err = w.loadArgsRule(d.Val())
		case "post_rule":
			d.NextArg()
			err = w.loadPostRule(d.Val())
		case "user_agent_rule":
			d.NextArg()
			err = w.loadUserAgentRule(d.Val())
		case "ip_allow_rule":
			d.NextArg()
			err = w.loadIpRule(d.Val(), false)
		case "ip_block_rule":
			d.NextArg()
			err = w.loadIpRule(d.Val(), true)
		case "rate_limit_bucket":
			d.NextArg()
			w.RateLimitBucket, _ = strconv.Atoi(d.Val())
		case "rate_limit_rate":
			d.NextArg()
			w.RateLimitRate, _ = strconv.ParseFloat(d.Val(), 64)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
// syntax:
//
//    waf {
//        args_rule             <path>
//        body_rule             <path>
//        user_agent_rule       <path>
//    }
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var t CaddyWaf
	err := t.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
