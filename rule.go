package waf

import (
	"bufio"
	"fmt"
	"html/template"
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

// redirectIntercept Intercept request
func (w *CaddyWaf) redirectIntercept(rw http.ResponseWriter) {
	var tpl *template.Template
	tpl, _ = template.New("default_listing").Parse(defaultWafTemplate)
	tpl.Execute(rw, nil)
}
