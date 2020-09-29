package waf

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"net/http"
)

type CaddyWaf struct {
	logger        *zap.Logger
	ArgsRule      []string
	UserAgentRule []string
	PostRule      []string
}

func init() {
	caddy.RegisterModule(CaddyWaf{})
}

// CaddyModule returns the Caddy module information.
func (CaddyWaf) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.waf",
		New: func() caddy.Module { return new(CaddyWaf) },
	}
}

func (w *CaddyWaf) Provision(ctx caddy.Context) error {
	w.logger = ctx.Logger(w) // g.logger is a *zap.Logger
	return nil
}

func (w *CaddyWaf) Validate() error {
	w.logger.Info("Validate.")
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (w CaddyWaf) ServeHTTP(rw http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

	if !w.detectRequestArgs(r) {
		return next.ServeHTTP(rw, r)
	}
	w.redirectIntercept(rw)
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*CaddyWaf)(nil)
	_ caddy.Validator             = (*CaddyWaf)(nil)
	_ caddyhttp.MiddlewareHandler = (*CaddyWaf)(nil)
)
