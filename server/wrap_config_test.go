package main

import (
	"testing"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
)

func TestPickServerWrapCipherHonorsClientPreference(t *testing.T) {
	aes := sessionproto.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM
	chacha := sessionproto.WrapCipher_WRAP_CIPHER_SRTP_CHACHA20_POLY1305
	none := sessionproto.WrapCipher_WRAP_CIPHER_NONE

	for _, tc := range []struct {
		name    string
		allowed []sessionproto.WrapCipher
		offered []sessionproto.WrapCipher
		want    sessionproto.WrapCipher
	}{
		{
			name:    "client prefers ChaCha, server allows both",
			allowed: []sessionproto.WrapCipher{aes, chacha},
			offered: []sessionproto.WrapCipher{chacha, aes},
			want:    chacha,
		},
		{
			name:    "client prefers AES, server allows both",
			allowed: []sessionproto.WrapCipher{aes, chacha},
			offered: []sessionproto.WrapCipher{aes, chacha},
			want:    aes,
		},
		{
			name:    "client prefers AES, server only allows ChaCha (downgrade)",
			allowed: []sessionproto.WrapCipher{chacha},
			offered: []sessionproto.WrapCipher{aes, chacha},
			want:    chacha,
		},
		{
			name:    "client prefers ChaCha, server only allows AES (downgrade)",
			allowed: []sessionproto.WrapCipher{aes},
			offered: []sessionproto.WrapCipher{chacha, aes},
			want:    aes,
		},
		{
			name:    "no overlap",
			allowed: []sessionproto.WrapCipher{aes},
			offered: []sessionproto.WrapCipher{chacha},
			want:    none,
		},
		{
			name:    "empty allowed",
			allowed: nil,
			offered: []sessionproto.WrapCipher{aes},
			want:    none,
		},
		{
			name:    "empty offered",
			allowed: []sessionproto.WrapCipher{aes},
			offered: nil,
			want:    none,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := pickServerWrapCipher(tc.allowed, tc.offered)
			if got != tc.want {
				t.Fatalf("pickServerWrapCipher(allowed=%v, offered=%v) = %v, want %v",
					tc.allowed, tc.offered, got, tc.want)
			}
		})
	}
}
