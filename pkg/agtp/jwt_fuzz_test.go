// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package agtp

import (
	"testing"
	"time"
)

func FuzzVerifySessionIdentityJWTRejectsMalformedCompactTokens(f *testing.F) {
	seeds := [][2]string{
		{"", ""},
		{"not-a-jwt", "not-a-jwt"},
		{"a.b.c", "d.e.f"},
		{
			signRawTestJWT(f, `{"alg":"HS256","typ":"JWT","kid":"manager-key","kid":"other"}`, `{"iss":"manager","sub":"agent-a","aud":"client-a","jti":"grant-dup","iat":1700000000,"exp":1700000060,"agtp_type":"agtp.identity-grant","agtp_version":"1","cnf":{"kid":"agent-key-1"}}`, []byte("manager-secret")),
			"not-a-binding",
		},
	}
	for _, seed := range seeds {
		f.Add(seed[0], seed[1])
	}

	now := time.Unix(1_700_000_000, 0)
	f.Fuzz(func(t *testing.T, grantToken, bindingToken string) {
		if len(grantToken) > 4096 || len(bindingToken) > 4096 {
			t.Skip()
		}
		_, _ = VerifySessionIdentityJWT(grantToken, bindingToken, testSessionIdentityOptions(now))
	})
}
