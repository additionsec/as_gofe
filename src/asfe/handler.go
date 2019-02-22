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
	"bytes"
	"io/ioutil"
	"net/http"
	"sync"
	"sync/atomic"
)

const (
	MaxStandardLength = (16 * 1024) // NOTE: ASMA report size/max is 64k
)

var (
	pool sync.Pool = sync.Pool{New: func() interface{} { return make([]byte, MaxStandardLength) }}
)

func handleMsg(w http.ResponseWriter, r *http.Request) {
	var body []byte
	var err error
	atomic.AddUint64(&StatRequest, 1)

	// We need a POST w/ a non-zero body length
	if r.Method != "POST" || r.ContentLength == 0 {
		atomic.AddUint64(&StatErrDiscarded, 1)
		w.WriteHeader(200)
		return
	}

	// Attempt to re-use a pool buffer
	if r.ContentLength > 1 && r.ContentLength < MaxStandardLength {
		poolBuf := pool.Get().([]byte)
		defer pool.Put(poolBuf)

		// Read into our existing buffer
		n, err := r.Body.Read(poolBuf)
		if err != nil {
			atomic.AddUint64(&StatErrBodyRead, 1)
			w.WriteHeader(500)
			return
		}

		// Slice the buffer down to the body length
		body = poolBuf[0:n]

	} else {
		atomic.AddUint64(&StatNonPool, 1)

		// Read in the body
		body, err = ioutil.ReadAll(r.Body)
		if err != nil {
			atomic.AddUint64(&StatErrBodyRead, 1)
			w.WriteHeader(500)
			return
		}
	}

	// Parse the protobuf to minimum necessary values
	pi, err := parseMsg(body)
	if err != nil {
		// Not parsable; if we return 500, the device will keep re-sending.
		// So we have to return 200 in order for device to purge from queue.
		atomic.AddUint64(&StatErrParse, 1)
		opQueueParseError(body)
		w.WriteHeader(200)
		return
	}

	// Create key
	key, err := createStorageKey(body, pi)
	if err != nil {
		atomic.AddUint64(&StatErrCreateKey, 1)
		w.WriteHeader(500)
		return
	}

	// Wrap the data in a readseeker
	rdr := bytes.NewReader(body)

	// Try to write to primary
	err = opStorePrimary(rdr, key)
	if err != nil {
		// Failed to put to primary; try secondary
		err = opStoreSecondary(rdr, key)
		if err != nil {
			// Failed to save to secondary
			atomic.AddUint64(&StatErrStore, 1)
			w.WriteHeader(500)
			return
		} else {
			atomic.AddUint64(&StatStoredSecondary, 1)
		}
	} else {
		atomic.AddUint64(&StatStoredPrimary, 1)
	}

	// If there is something atypical in the msg, then submit it for further inspection
	if pi.Atypical {
		atomic.AddUint64(&StatAtypical, 1)
		opQueueAtypical(body)
	}

	atomic.AddUint64(&StatOK, 1)
	w.WriteHeader(200)
}
