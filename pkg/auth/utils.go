package auth

import (
	"fmt"
	"net/url"
	"path"
)

func buildURL(basePath string, relPath string, args ...interface{}) string {
	u, _ := url.Parse(basePath)
	u.Path = path.Join(u.Path, fmt.Sprintf(relPath, args...))
	urlResult, _ := url.PathUnescape(u.String())
	return urlResult
}
