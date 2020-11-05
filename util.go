package apple_validate

import (
	"encoding/base64"
	"strings"
	"unsafe"
)

func decodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}

func decodeBase64String(src string) ([]byte, error) {
	var isRaw = !strings.HasSuffix(src, "=")
	if strings.Contains(src, "+/") {
		if isRaw {
			return base64.RawStdEncoding.DecodeString(src)
		}
		return base64.StdEncoding.DecodeString(src)
	}
	if isRaw {
		return base64.RawURLEncoding.DecodeString(src)
	}
	return base64.URLEncoding.DecodeString(src)
}

func bytes2String(bytes []byte) string {
	return *(*string)(unsafe.Pointer(&bytes))
}
