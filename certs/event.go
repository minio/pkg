// Copyright (c) 2015-2021 MinIO, Inc.
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

package certs

import (
	"runtime"
	"time"

	"github.com/rjeczalik/notify"
)

// isWriteEvent checks if the event returned is a write event
func isWriteEvent(event notify.Event) bool {
	for _, ev := range eventWrite {
		if event&ev != 0 {
			return true
		}
	}
	return false
}

// watchDirSafe watches a directory for write events and sends notifications
// to ch. On Windows, rjeczalik/notify uses unsafe pointer casts that crash
// under Go's checkptr validation, so we fall back to polling with eventPath
// as the reported path in synthetic events.
func watchDirSafe(dir, eventPath string, ch chan notify.EventInfo, done <-chan struct{}) (stop func(), err error) {
	if runtime.GOOS == "windows" {
		quit := make(chan struct{})
		exited := make(chan struct{})
		go func() {
			defer close(exited)
			t := time.NewTicker(symlinkReloadInterval)
			defer t.Stop()
			for {
				select {
				case <-quit:
					return
				case <-done:
					return
				case <-t.C:
					select {
					case ch <- eventInfo{eventPath, notify.Write}:
					default:
					}
				}
			}
		}()
		return func() { close(quit); <-exited }, nil
	}
	if err := notify.Watch(dir, ch, eventWrite...); err != nil {
		return nil, err
	}
	return func() { notify.Stop(ch) }, nil
}
