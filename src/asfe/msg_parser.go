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
	//"log"
	"errors"
	"sync/atomic"

	"github.com/golang/protobuf/proto"
)

var (
	MsgParseError error = errors.New("Message parse error")
	AtypicalMap   [512]byte
)

type ParsedInfo struct {
	OrgId    []byte
	SysId    []byte
	AppId    []byte
	SysType  uint32
	Atypical bool
	Fdc      bool
}

func parseInit() {
	AtypicalMap[250] = 1
	AtypicalMap[251] = 1
	AtypicalMap[252] = 1
	AtypicalMap[253] = 1
	AtypicalMap[254] = 1
	AtypicalMap[255] = 1

	AtypicalMap[300] = 1
	AtypicalMap[302] = 1
	AtypicalMap[305] = 1
	AtypicalMap[306] = 1
	AtypicalMap[307] = 1
	AtypicalMap[308] = 1
	AtypicalMap[309] = 1
	AtypicalMap[310] = 1
	AtypicalMap[311] = 1
	AtypicalMap[312] = 1
	AtypicalMap[313] = 1
	AtypicalMap[314] = 1
	AtypicalMap[315] = 1
	AtypicalMap[317] = 1
	AtypicalMap[318] = 1

	AtypicalMap[400] = 1
	AtypicalMap[401] = 1
	AtypicalMap[402] = 1
	AtypicalMap[403] = 1
	AtypicalMap[405] = 1
	AtypicalMap[406] = 1
	AtypicalMap[409] = 1
	AtypicalMap[410] = 1
	AtypicalMap[411] = 1
	AtypicalMap[412] = 1
	AtypicalMap[413] = 1
	AtypicalMap[414] = 1
	AtypicalMap[416] = 1
	AtypicalMap[417] = 1
	AtypicalMap[418] = 1

	AtypicalMap[500] = 1
	AtypicalMap[501] = 1
	AtypicalMap[502] = 1
	AtypicalMap[503] = 1
	AtypicalMap[504] = 1
	AtypicalMap[505] = 1

}

func processTest(test uint32, pi *ParsedInfo) {
	//log.Println("Test: ", test);
	if test == 99 {
		pi.Fdc = true
	} else if test < 250 || test > 512 {
		return
	} else if AtypicalMap[test] > 0 {
		pi.Atypical = true
	}
}

func parseMsg(data []byte) (*ParsedInfo, error) {

	// Addition Security uses a hand-crafted, deterministic protobuf encoder.  So we will
	// first parse against that encoder, since it *should* be the only thing we encounter.
	// If for some reason the format doesn't pan out, we will fall back to a more generic
	// protobuf decoder.  We do this for performance reasons.

	pi := &ParsedInfo{}

	L := uint32(len(data))

	// Addition security exact header format/order
	// First tag is Report.Version (tag=10, 4 bytes)
	// Next tag is Report.OrganizationId (tag=1, 32 bytes)
	// Next tag is Report.SystemId (tag=2, 32 bytes)
	// Next tag is Report.SystemType (tag=4, 1 byte)
	// Next tag is Report.applicationId (tag=5, variable bytes)
	// Next optional tag is Report.userIdSecondary (tag=7, variable bytes)
	// After that, we should be into sightings
	if L > 0x4d &&
		data[0] == 0x52 && data[1] == 0x04 &&
		data[0x06] == 0x0a && data[0x07] == 0x20 &&
		data[0x28] == 0x12 && data[0x29] == 0x20 &&
		data[0x4a] == 0x20 && data[0x4b] < 0x7f &&
		data[0x4c] == 0x2a && data[0x4d] <= 0x7f {

		// We are not going to parse the version
		pi.OrgId = data[0x08:0x28]
		pi.SysId = data[0x2a:0x4a]
		pi.SysType = uint32(data[0x4b])

		appIdLen := uint32(data[0x4d])
		if L < (0x4e + appIdLen) {
			// We could fall through, but if we get here it means we don't have
			// enough data -- the other parser will fail too
			return nil, MsgParseError
		}
		pi.AppId = data[0x4e : 0x4e+appIdLen]

		var offset uint32 = 0x4e + appIdLen

		// There may be optional user2 tag present (tag=7, variable bytes)
		if data[offset] == 0x3a {
			offset++
			// Only parse if it's a reasonable amount
			if data[offset] >= 0x80 {
				goto fallback
			}

			offset += uint32(data[offset])
			offset++
			if L <= offset {
				return nil, MsgParseError
			}
		}

		// Walk the Sightings (tag=8, variable length)
		var slen, test, end uint32
		for L > offset && data[offset] == 0x42 { // Sightings tag
			offset++

			// Decode the whole sightings length
			// NOTE: two bytes allows up to 14 bits/16k of data without falling back
			slen = uint32(data[offset])
			if slen >= 0x80 {
				offset++
				if data[offset] >= 0x80 {
					goto fallback
				}
				slen = (slen & 0x7f) | (uint32(data[offset]) << 7)
			}
			offset++

			end = offset + slen
			if L < end || slen < 2 {
				goto fallback
			}

			// Test ID (tag=6) is always the first sightings (sub) tag
			if data[offset] != 0x30 {
				// Not in expected order
				goto fallback
			}
			offset++

			// NOTE: two bytes allows up to 14 bits/test ID values <= 16k
			test = uint32(data[offset])
			if test >= 0x80 {
				offset++
				if data[offset] >= 0x80 {
					goto fallback
				}
				test = (test & 0x7f) | (uint32(data[offset]) << 7)
			}
			//offset++

			processTest(test, pi)

			offset = end
		}

		if offset != L {
			goto fallback
		}

		return pi, nil
	}

fallback:
	atomic.AddUint64(&StatParseFallback, 1)

	rep := &Report{}
	err := proto.Unmarshal(data, rep)
	if err != nil {
		//log.Fatal("unmarsh: ", err)
		return nil, MsgParseError
	}

	pi.OrgId = rep.GetOrganizationId()
	pi.SysId = rep.GetSystemId()
	pi.AppId = rep.GetApplicationId()
	pi.SysType = rep.GetSystemType()
	if pi.OrgId == nil || pi.SysId == nil || pi.AppId == nil || pi.SysType == 0 {
		return nil, MsgParseError
	}

	sightings := rep.GetSightings()
	if sightings != nil {
		for _, s := range sightings {
			processTest(s.GetTestId(), pi)
		}
	}

	return pi, nil
}
