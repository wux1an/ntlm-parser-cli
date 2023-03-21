package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	parser "github.com/wux1an/ntlm-parser"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <base64|hex|url>\n", filepath.Base(os.Args[0]))
		os.Exit(-1)
	}

	var (
		str              = os.Args[1]
		buf              []byte
		base64Buf, err1  = base64.StdEncoding.DecodeString(str)
		hexBuf, err2     = hex.DecodeString(str)
		requestUrl, err3 = url.Parse(str)
	)

	if err3 == nil && requestUrl.Scheme != "" {
		var req, err = http.NewRequest(http.MethodGet, requestUrl.String(), nil)
		if err != nil {
			fmt.Printf("failed to access %s, %v\n", requestUrl.String(), err)
			os.Exit(-1)
		}
		req.Header.Set("Authorization", "NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=")
		req.Header.Set("User-Agent", "") // remove default useragent header

		var client = http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // dont check certificate
				},
			},
		}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("failed to access %s, %v\n", requestUrl.String(), err)
			os.Exit(-1)
		}

		var auth = resp.Header.Get("WWW-Authenticate")
		if !strings.HasPrefix(auth, "NTLM ") {
			fmt.Printf("the authentication mode for this target is not ntlm (WWW-Authenticate: %s)", auth)
			os.Exit(-1)
		}

		auth = strings.TrimPrefix(auth, "NTLM ")
		buf, err = base64.StdEncoding.DecodeString(auth)
	} else if err2 == nil {
		buf = hexBuf
	} else if err1 == nil {
		buf = base64Buf
	} else {
		fmt.Println("please provide a valid base64 or hex string or url")
		os.Exit(-1)
	}

	if result, err := parser.FromBytes(buf); err != nil {
		fmt.Printf("formatting failed, %v\n", err)
		os.Exit(-1)
	} else {
		switch result.(type) {
		case *parser.NTLMType2:
			var type2 = result.(*parser.NTLMType2)
			var jsonStr, _ = json.MarshalIndent(type2.TargetInfoWrapper(), "", "  ")
			var vv = type2.OsVersionStructure.LongString()
			fmt.Printf("CHALLENGE_MESSAGE (type 2)\n")
			fmt.Printf("OS Version:  %s\n", vv)
			fmt.Printf("TargetInfo:  %s\n", jsonStr)
		default:
			var jsonStr, _ = json.MarshalIndent(result, "", "  ")
			fmt.Println(jsonStr)
		}
	}
}
