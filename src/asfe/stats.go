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
	"strconv"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sns"
)

const (
	StatsDuration = 1 * time.Minute
)

var (
	StatErrParse           uint64
	StatErrDiscarded       uint64
	StatErrBodyRead        uint64
	StatErrCreateKey       uint64
	StatErrStore           uint64
	StatErrQueueParseError uint64
	StatErrQueueAtypical   uint64
	StatErrConfigRefresh   uint64
	StatErrStatReport      uint64

	StatQueueFullAtypical   uint64
	StatQueueFullParseError uint64

	StatOK              uint64
	StatRequest         uint64
	StatAtypical        uint64
	StatNonPool         uint64
	StatStoredPrimary   uint64
	StatStoredSecondary uint64
	StatParseFallback   uint64
	StatConfigRefresh   uint64
)

func statsWorker() {
	sess = session.Must(session.NewSession())
	cfg = aws.NewConfig().WithMaxRetries(2)

	for _ = range time.Tick(StatsDuration) {

		mc := (*Config)(atomic.LoadPointer(&MainConfig))
		if mc.TopicStats == nil {
			continue
		}

		snsc := sns.New(sess, cfg.WithRegion(mc.TopicStats[0]))
		var buffer bytes.Buffer

		buffer.WriteString("Requests: ")
		buffer.WriteString(strconv.FormatUint(atomic.LoadUint64(&StatRequest), 10))

		buffer.WriteString("\nOK: ")
		buffer.WriteString(strconv.FormatUint(atomic.LoadUint64(&StatOK), 10))

		buffer.WriteString("\nStoredPrimary: ")
		buffer.WriteString(strconv.FormatUint(atomic.LoadUint64(&StatStoredPrimary), 10))

		buffer.WriteString("\nStoredSecondary: ")
		buffer.WriteString(strconv.FormatUint(atomic.LoadUint64(&StatStoredSecondary), 10))

		buffer.WriteString("\nAtypical: ")
		buffer.WriteString(strconv.FormatUint(atomic.LoadUint64(&StatAtypical), 10))

		buffer.WriteString("\nNonpool: ")
		buffer.WriteString(strconv.FormatUint(atomic.LoadUint64(&StatNonPool), 10))

		buffer.WriteString("\nParseFallback: ")
		buffer.WriteString(strconv.FormatUint(atomic.LoadUint64(&StatParseFallback), 10))

		buffer.WriteString("\nConfigRefresh: ")
		buffer.WriteString(strconv.FormatUint(atomic.LoadUint64(&StatConfigRefresh), 10))

		buffer.WriteString("\nErrParse: ")
		buffer.WriteString(strconv.FormatUint(atomic.LoadUint64(&StatErrParse), 10))

		buffer.WriteString("\nErrDiscarded: ")
		buffer.WriteString(strconv.FormatUint(atomic.LoadUint64(&StatErrDiscarded), 10))

		buffer.WriteString("\nErrBodyRead: ")
		buffer.WriteString(strconv.FormatUint(atomic.LoadUint64(&StatErrBodyRead), 10))

		buffer.WriteString("\nErrCreateKey: ")
		buffer.WriteString(strconv.FormatUint(atomic.LoadUint64(&StatErrCreateKey), 10))

		buffer.WriteString("\nErrStore: ")
		buffer.WriteString(strconv.FormatUint(atomic.LoadUint64(&StatErrStore), 10))

		buffer.WriteString("\nErrQParse: ")
		buffer.WriteString(strconv.FormatUint(atomic.LoadUint64(&StatErrQueueParseError), 10))

		buffer.WriteString("\nErrQAtypical: ")
		buffer.WriteString(strconv.FormatUint(atomic.LoadUint64(&StatErrQueueAtypical), 10))

		buffer.WriteString("\nErrConfigRefresh: ")
		buffer.WriteString(strconv.FormatUint(atomic.LoadUint64(&StatErrConfigRefresh), 10))

		buffer.WriteString("\nErrStatReport: ")
		buffer.WriteString(strconv.FormatUint(atomic.LoadUint64(&StatErrStatReport), 10))

		buffer.WriteString("\nQFullParse: ")
		buffer.WriteString(strconv.FormatUint(atomic.LoadUint64(&StatQueueFullParseError), 10))

		buffer.WriteString("\nQFullAtypical: ")
		buffer.WriteString(strconv.FormatUint(atomic.LoadUint64(&StatQueueFullAtypical), 10))

		input := &sns.PublishInput{
			Message:  aws.String(buffer.String()),
			TopicArn: aws.String(mc.TopicStats[1]),
		}
		if _, err := snsc.Publish(input); err != nil {
			atomic.AddUint64(&StatErrStatReport, 1)
		}
	}

}

func statsInit() {
	go statsWorker()
}
