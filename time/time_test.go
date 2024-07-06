// Copyright (c) 2015-2024 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package time

import (
	"testing"
	"time"
)

func TestParseTimeDuration(t *testing.T) {
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
			name:    "test6",
			args:    args{durStr: "-7d1h"},
			want:    (7*24*time.Hour + time.Hour) * -1,
			wantErr: false,
		},
		{
			name:    "test7",
			args:    args{durStr: "7d-1h"},
			wantErr: true,
		},
		{
			name:    "test8",
			args:    args{durStr: "-7d-1h"},
			wantErr: true,
		},
		{
			name:    "test9",
			args:    args{durStr: "0.1h"},
			want:    time.Minute * 6,
			wantErr: false,
		},
		{
			name:    "test10",
			args:    args{durStr: "1.1d0.1h"},
			want:    time.Hour*24 + time.Hour*2 + time.Minute*30,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTimeDuration(tt.args.durStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTimeDuration() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseTimeDuration() got = %v, want %v", got, tt.want)
			}
		})
	}
}
