// Copyright 2019 J Forristal LLC
// Copyright 2016 Addition Security Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package asfe

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"sync/atomic"
	"time"
	"unsafe"
)

const (
	ConfigRefreshDuration = 5 * time.Minute
)

var (
	MainConfig unsafe.Pointer
)

type Config struct {
	StoragePrimary   []string `json:"storagePrimary"`
	StorageSecondary []string `json:"storageSecondary,omitempty"`
	QueueParseError  []string `json:"queueParseError,omitempty"`
	QueueAtypical    []string `json:"queueAtypical,omitempty"`
	TopicStats       []string `json:"topicStats,omitempty"`
}

func configRefresher(url string) {

	c := time.Tick(ConfigRefreshDuration)

	for _ = range c {
		resp, err := http.Get(url)
		if err != nil {
			atomic.AddUint64(&StatErrConfigRefresh, 1)
			continue
		}

		data, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			atomic.AddUint64(&StatErrConfigRefresh, 1)
			continue
		}

		config := &Config{}
		if err = json.Unmarshal(data, config); err != nil {
			atomic.AddUint64(&StatErrConfigRefresh, 1)
			continue
		}

		atomic.StorePointer(&MainConfig, unsafe.Pointer(config))
		atomic.AddUint64(&StatConfigRefresh, 1)
	}
}

func ConfigInit(url string) error {

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	config := &Config{}
	if err := json.Unmarshal(data, config); err != nil {
		return err
	}

	atomic.StorePointer(&MainConfig, unsafe.Pointer(config))

	go configRefresher(url)

	return nil
}
