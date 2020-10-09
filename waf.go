package waf

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

type CaddyWaf struct {
	logger        *zap.Logger
	ArgsRule      []string
	UserAgentRule []string
	PostRule      []string
	IpAllowRule   []string
	IpBlockRule   []string
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

	remoteAddr := w.getRemoteIp(r)

	//ip allow rule
	if w.detectIp(remoteAddr, false) {
		return next.ServeHTTP(rw, r)
	}

	//ip deny rule
	if w.detectIp(remoteAddr, true) {
		return w.redirectIntercept(rw)
	}

	if w.detectRequestArgs(r) {
		return w.redirectIntercept(rw)
	}

	if w.detectRequestBody(r) {
		return w.redirectIntercept(rw)
	}

	if w.detectUserAgent(r) {
		return w.redirectIntercept(rw)
	}

	return next.ServeHTTP(rw, r)
}

func (w CaddyWaf) getRemoteIp(r *http.Request) string {
	i := strings.Index(r.RemoteAddr, ":")
	if i < 1 {
		return r.RemoteAddr
	}
	return r.RemoteAddr[:i]
}

func (w CaddyWaf) Start() error {
	w.logger.Info("App start.")
	return nil
}

func (w CaddyWaf) Stop() error {
	w.logger.Info("App stop.")
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*CaddyWaf)(nil)
	_ caddy.Validator             = (*CaddyWaf)(nil)
	_ caddyhttp.MiddlewareHandler = (*CaddyWaf)(nil)
	_ caddy.App                   = (*CaddyWaf)(nil)
)
