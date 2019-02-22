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
	"encoding/binary"
	"encoding/hex"
	"sync/atomic"
	"time"
	//"github.com/minio/blake2b-simd"
)

var (
	ctr uint64 = 1
	ts  []byte
)

func utilsInit() {

	ts = []byte(time.Now().Format(time.RFC3339)[0:19] + "_")

	go func() {
		for _ = range time.Tick(time.Duration(1) * time.Second) {
			ts = []byte(time.Now().Format(time.RFC3339)[0:19] + "_")
		}
	}()
}

func createStorageKey(data []byte, pi *ParsedInfo) (string, error) {

	digest := make([]byte, 12)
	l := binary.PutUvarint(digest, atomic.AddUint64(&ctr, 1))
	digest = digest[0:l]

	// Allocate an output buffer
	// "/" + org + "/" + app "_" + type + "/" + sys + "/" + ts + digest
	out := make([]byte, (1 + 64 + 1 + len(pi.AppId) + 2 + 1 + 64 + 1 + len(ts) + (len(digest) * 2)))

	// Piece together our values
	out[0] = '/'
	hex.Encode(out[1:], pi.OrgId)

	out[65] = '/'
	copy(out[66:], pi.AppId)

	off := 66 + len(pi.AppId)
	out[off] = '_'
	off++
	out[off] = byte(0x40 + pi.SysType)
	off++

	out[off] = '/'
	off++
	hex.Encode(out[off:], pi.SysId)
	off += 64

	out[off] = '/'
	off++
	copy(out[off:], ts)
	off += len(ts)

	hex.Encode(out[off:], digest)

	return string(out), nil
}
