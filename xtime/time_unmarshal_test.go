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

package xtime

import (
	"encoding/json"
	"testing"

	"gopkg.in/yaml.v3"
)

type testDuration struct {
	A               string    `yaml:"a" json:"a"`
	Dur             Duration  `yaml:"dur" json:"dur"`
	DurationPointer *Duration `yaml:"durationPointer" json:"durationPointer"`
}

func TestDuration_Unmarshal(t *testing.T) {
	jsonData := []byte(`{"a":"1s","dur":"1w1s","durationPointer":"7d1s"}`)
	yamlData := []byte(`a: 1s
dur: 1w1s
durationPointer: 7d1s`)
	yamlTest := testDuration{}
	if err := yaml.Unmarshal(yamlData, &yamlTest); err != nil {
		t.Fatal(err)
	}
	jsonTest := testDuration{}
	if err := json.Unmarshal(jsonData, &jsonTest); err != nil {
		t.Fatal(err)
	}

	jsonData = []byte(`{"a":"1s","dur":"1w1s"}`)
	yamlData = []byte(`a: 1s
dur: 1w1s`)

	if err := yaml.Unmarshal(yamlData, &yamlTest); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(jsonData, &jsonTest); err != nil {
		t.Fatal(err)
	}

}
