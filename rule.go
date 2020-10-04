package waf

import (
	"bufio"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"regexp"
)

func (w *CaddyWaf) loadArgsRule(rulePath string) error {
	var err error
	w.ArgsRule, err = loadRule(rulePath)
	return err
}

func (w *CaddyWaf) loadPostRule(rulePath string) error {
	var err error
	w.PostRule, err = loadRule(rulePath)
	return err
}

func (w *CaddyWaf) loadUserAgentRule(rulePath string) error {
	var err error
	w.UserAgentRule, err = loadRule(rulePath)
	return err
}

func (w *CaddyWaf) loadIpRule(ipPath string, isBlock bool) error {
	ipRule, err := loadRule(ipPath)
	if isBlock {
		w.IpBlockRule = ipRule
	} else {
		w.IpAllowRule = ipRule
	}
	return err

}

func loadRule(rulePath string) ([]string, error) {
	file, err := os.Open(rulePath)
	if err != nil {
		return nil, fmt.Errorf("parsing rule file error: %v", err)
	}
	rule := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		rule = append(rule, scanner.Text())
	}

	return rule, nil
}

// detectAllowIp
func (w *CaddyWaf) detectIp(ipAddr string, isBlock bool) bool {

	var ipRule []string
	if isBlock {
		ipRule = w.IpBlockRule
	} else {
		ipRule = w.IpAllowRule
	}
	ip := net.ParseIP(ipAddr)
	for _, rule := range ipRule {
		_, ipNet, err := net.ParseCIDR(rule)
		if err != nil {
			if ip.Equal(net.ParseIP(rule)) {
				return true
			}
			continue
		}
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}

// detectRequestArgs
func (w *CaddyWaf) detectRequestArgs(r *http.Request) bool {
	for _, rule := range w.ArgsRule {
		reg, err := regexp.Compile(rule)
		if err != nil {
			continue
		}
		if reg.MatchString(r.RequestURI) {
			return true
		}
	}
	return false
}

// detectUserAgent
func (w *CaddyWaf) detectUserAgent(r *http.Request) bool {
	userAgent := r.UserAgent()
	for _, rule := range w.UserAgentRule {
		reg, err := regexp.Compile(rule)
		if err != nil {
			continue
		}

		if reg.MatchString(userAgent) {
			return true
		}
	}

	return false
}

// redirectIntercept Intercept request
func (w *CaddyWaf) redirectIntercept(rw http.ResponseWriter) error {
	var tpl *template.Template
	tpl, _ = template.New("default_listing").Parse(defaultWafTemplate)
	return tpl.Execute(rw, nil)
}
