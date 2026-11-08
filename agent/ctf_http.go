package agent

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Build a request for the same isolated runner/evidence recorder as other CTF
// tools. Argument values are quoted individually; no caller-supplied curl flags
// or application-host request executor are used.
func ctfHTTPCommand(args map[string]json.RawMessage) (string, int, error) {
	raw, err := json.Marshal(args)
	if err != nil {
		return "", 0, err
	}
	if len(raw) > 128<<10 {
		return "", 0, fmt.Errorf("HTTP 参数超过 128 KiB")
	}
	var in struct {
		URL     string            `json:"url"`
		Method  string            `json:"method"`
		Headers map[string]string `json:"headers"`
		Query   map[string]string `json:"query"`
		Form    map[string]string `json:"form"`
		Body    string            `json:"body"`
		Follow  bool              `json:"follow_redirects"`
		Cookies *bool             `json:"use_cookies"`
		Timeout int               `json:"timeout_seconds"`
	}
	if err = json.Unmarshal(raw, &in); err != nil {
		return "", 0, fmt.Errorf("HTTP 参数无效：%w", err)
	}
	u, err := url.Parse(in.URL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || strings.ContainsAny(in.URL, "\r\n\x00") {
		return "", 0, fmt.Errorf("请提供完整的 HTTP/HTTPS 题目 URL；账号信息请通过请求头传入")
	}
	query := u.Query()
	for k, v := range in.Query {
		query.Set(k, v)
	}
	// Preserve an explicitly supplied query verbatim unless query parameters
	// were provided; CTF requests may intentionally contain unusual encodings.
	if len(in.Query) > 0 {
		u.RawQuery = query.Encode()
	}
	if len(in.Form) > 0 && in.Body != "" {
		return "", 0, fmt.Errorf("form 与 body 不能同时提供")
	}
	if len(in.Form) > 0 {
		form := url.Values{}
		for k, v := range in.Form {
			form.Set(k, v)
		}
		in.Body = form.Encode()
		if in.Headers == nil {
			in.Headers = map[string]string{}
		}
		hasContentType := false
		for k := range in.Headers {
			hasContentType = hasContentType || strings.EqualFold(k, "Content-Type")
		}
		if !hasContentType {
			in.Headers["Content-Type"] = "application/x-www-form-urlencoded"
		}
	}
	if len(in.Body) > 64<<10 || len(in.Headers) > 64 || len(u.String()) > 16<<10 || strings.ContainsRune(in.Body, 0) {
		return "", 0, fmt.Errorf("请求超过限制：正文 64 KiB、64 个请求头、URL 16 KiB")
	}
	in.Method = strings.ToUpper(strings.TrimSpace(in.Method))
	if in.Method == "" {
		in.Method = "GET"
		if in.Body != "" || len(in.Form) > 0 {
			in.Method = "POST"
		}
	}
	switch in.Method {
	case "GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS":
	default:
		return "", 0, fmt.Errorf("不支持的 HTTP 方法")
	}
	if in.Timeout <= 0 {
		in.Timeout = 30
	}
	in.Timeout = min(in.Timeout, 120)
	parts := []string{"curl", "--silent", "--show-error", "--path-as-is", "--globoff", "--proto", quote("=http,https"), "--proto-redir", quote("=http,https"), "--connect-timeout", fmt.Sprint(min(in.Timeout, 15)), "--max-time", fmt.Sprint(in.Timeout), "--max-filesize", "8388608", "--max-redirs", "3"}
	if in.Method == "HEAD" {
		parts = append(parts, "--head")
	} else {
		parts = append(parts, "--request", quote(in.Method))
	}
	if in.Follow {
		parts = append(parts, "--location")
	}
	if in.Cookies == nil || *in.Cookies {
		parts = append(parts, "--cookie", ".ctf-http-cookies", "--cookie-jar", ".ctf-http-cookies")
	}
	keys := make([]string, 0, len(in.Headers))
	for k, v := range in.Headers {
		if strings.TrimSpace(k) == "" || strings.ContainsAny(k, ": \t\r\n\x00") || strings.ContainsAny(v, "\r\n\x00") || len(k)+len(v) > 8192 {
			return "", 0, fmt.Errorf("HTTP 请求头名称或内容无效")
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, "--header", quote(k+": "+in.Headers[k]))
	}
	if in.Body != "" || in.Form != nil {
		parts = append(parts, "--data-raw", quote(in.Body))
	}
	bodyPath := "http/response-body.txt"
	if in.Method == "HEAD" {
		bodyPath = "/dev/null"
	}
	parts = append(parts, "--dump-header", "http/response-headers.txt", "--output", bodyPath, "--write-out", quote("HTTP status: %{http_code}\nEffective URL: %{url_effective}\n"), "--url", quote(u.String()))
	// Clear old responses before curl so a failed connection cannot replay an
	// earlier body/Flag as evidence for a new execution. Preserve curl's exit code.
	command := "mkdir -p http || exit 1\n: > http/response-headers.txt || exit 1\n: > http/response-body.txt || exit 1\n: > http/response-meta.txt || exit 1\n" + strings.Join(parts, " ") + " > http/response-meta.txt\nctf_http_exit=$?\ncat http/response-headers.txt\nprintf '\\n'\ncat http/response-body.txt\nprintf '\\n'\ncat http/response-meta.txt\nexit \"$ctf_http_exit\""
	if len(command) > 240<<10 {
		return "", 0, fmt.Errorf("请求编码后超过执行器命令大小限制")
	}
	return command, in.Timeout + 10, nil
}
