package client

import (
	"fmt"
	"net/url"
	"strings"
)

// normalizeBaseURL strips the trailing slash and rejects anything that is not
// an absolute http(s) URL, so a misconfigured host fails at startup instead of
// on the first API call.
func normalizeBaseURL(baseURL string) (string, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if trimmed == "" {
		return "", fmt.Errorf("base URL is empty")
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid base URL %q: %w", trimmed, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("invalid base URL %q: must include an http:// or https:// scheme", trimmed)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("invalid base URL %q: missing host", trimmed)
	}

	return trimmed, nil
}

func withRoles() ReqOpt {
	return withQueryParam("withRoles", "true")
}

func withQueryParam(key string, value string) ReqOpt {
	return func(reqURL *url.URL) {
		q := reqURL.Query()
		q.Set(key, value)
		reqURL.RawQuery = q.Encode()
	}
}

func parseTagNames(objs []TenableObject) []TenableObject {
	for i, obj := range objs {
		if obj.Type == "Tag" {
			objs[i].Name = strings.Replace(obj.Name, ":", ",", 1)
		}
	}
	return objs
}
