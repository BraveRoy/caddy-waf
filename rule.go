package waf

import (
	"bufio"
	"bytes"
	"fmt"
	"html/template"
	"io/ioutil"
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

func (w *CaddyWaf) loadIpRule(rulePath string, isBlock bool) error {
	ipRule, err := loadRule(rulePath)
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

// detectRequestBody
func (w *CaddyWaf) detectRequestBody(r *http.Request) bool {

	//仅拦截post 类型的请求, 检测body实体里面是否有违规内容
	if r.Method != "POST" {
		return false
	}

	body, _ := ioutil.ReadAll(r.Body)
	r.Body.Close() //  must close
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	if len(body) == 0 {
		return false
	}

	for _, rule := range w.PostRule {
		reg, err := regexp.Compile(rule)
		if err != nil {
			continue
		}
		if reg.MatchString(string(body)) {
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
	rw.WriteHeader(http.StatusNotImplemented)
	tpl, _ = template.New("default_listing").Parse(defaultWafTemplate)
	return tpl.Execute(rw, nil)
}
