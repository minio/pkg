package cmd

import (
	"testing"
	"time"
)

func TestParseTimeDurationSimply(t *testing.T) {
	type args struct {
		durStr string
	}
	tests := []struct {
		name    string
		args    args
		want    time.Duration
		wantErr bool
	}{
		{
			name:    "test1",
			args:    args{durStr: "1h"},
			want:    time.Hour,
			wantErr: false,
		},
		{
			name:    "test2",
			args:    args{durStr: "1h30m30s"},
			want:    time.Hour + 30*time.Minute + 30*time.Second,
			wantErr: false,
		},
		{
			name:    "test3",
			args:    args{durStr: "1h30m30s30m"}, // duplicate minute
			wantErr: true,
		},
		{
			name:    "test4",
			args:    args{durStr: "7d"},
			want:    7 * 24 * time.Hour,
			wantErr: false,
		},
		{
			name:    "test5",
			args:    args{durStr: "7d1h"},
			want:    7*24*time.Hour + time.Hour,
			wantErr: false,
		},
		{
			name:    "test5",
			args:    args{durStr: "-7d1h"},
			want:    (7*24*time.Hour + time.Hour) * -1,
			wantErr: false,
		},
		{
			name:    "test6",
			args:    args{durStr: "7d-1h"},
			wantErr: true,
		},
		{
			name:    "test6",
			args:    args{durStr: "-7d-1h"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTimeDurationSimply(tt.args.durStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTimeDurationSimply() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseTimeDurationSimply() got = %v, want %v", got, tt.want)
			}
		})
	}
}
