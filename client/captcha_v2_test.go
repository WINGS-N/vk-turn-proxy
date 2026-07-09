package main

import "testing"

func TestExtractDebugInfoV2(t *testing.T) {
	const hash = "59f60d917b13be6a22c076adb2c17df37302c5314d8353a27e72f9fbcc9b4838"
	tests := []struct {
		name     string
		body     string
		want     string
		fallback bool
		wantErr  bool
	}{
		{
			name: "primary wrapped pattern",
			body: `x=debug_info:(window.vk.abc)||"` + hash + `";`,
			want: hash, fallback: false,
		},
		{
			name: "primary bare pattern",
			body: `debug_info:"` + hash + `"`,
			want: hash, fallback: false,
		},
		{
			name: "windowed fallback on wrapper drift",
			body: `debug_info=someNewWrapper(),then later "` + hash + `" appears`,
			want: hash, fallback: true,
		},
		{
			name:    "marker missing",
			body:    `no marker at all "` + hash + `"`,
			wantErr: true,
		},
		{
			name:    "marker present but no hash in window",
			body:    `debug_info then nothing hex-shaped for a while ................................................................................................`,
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, fb, err := extractDebugInfoV2([]byte(tc.body))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got value %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want || fb != tc.fallback {
				t.Fatalf("got (%q, fallback=%v), want (%q, fallback=%v)", got, fb, tc.want, tc.fallback)
			}
		})
	}
}
