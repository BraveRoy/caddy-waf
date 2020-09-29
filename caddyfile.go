package waf

import (
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("waf", parseCaddyfile)
}

// UnmarshalCaddyfile
func (w *CaddyWaf) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.NextArg()
	for d.NextBlock(0) {
		switch d.Val() {
		case "args_rule":
			d.NextArg()
			w.loadArgsRule(d.Val())
		case "post_rule":
			d.NextArg()
			w.loadPostRule(d.Val())
		case "user_agent_rule":
			d.NextArg()
			w.loadUserAgentRule(d.Val())
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
