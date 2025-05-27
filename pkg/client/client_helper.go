package client

import (
	"net/url"
	"strings"
)

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
