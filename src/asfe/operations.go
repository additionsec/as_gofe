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
	"encoding/base64"
	"errors"
	"io"
	"sync/atomic"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sqs"
)

const (
	QUEUE_SIZE_PARSEERROR = 1000
	QUEUE_SIZE_ATYPICAL   = 1000
)

var (
	sess = session.Must(session.NewSession())
	cfg  = aws.NewConfig().WithMaxRetries(2)

	NotConfiguredError = errors.New("Not configured")

	chanParseError = make(chan []byte, QUEUE_SIZE_PARSEERROR)
	chanAtypical   = make(chan []byte, QUEUE_SIZE_ATYPICAL)
)

func opInit() {

	go func() {
		for data := range chanParseError {
			_opQueueParseError(data)
		}
	}()

	go func() {
		for data := range chanAtypical {
			_opQueueAtypical(data)
		}
	}()
}

func _opQueueParseError(data []byte) {
	mc := (*Config)(atomic.LoadPointer(&MainConfig))
	if mc.QueueParseError == nil {
		return
	}
	sqsc := sqs.New(sess, cfg.WithRegion(mc.QueueParseError[0]))

	input := &sqs.SendMessageInput{
		QueueUrl:    aws.String(mc.QueueParseError[1]),
		MessageBody: aws.String(base64.StdEncoding.EncodeToString(data)),
	}

	if _, err := sqsc.SendMessage(input); err != nil {
		atomic.AddUint64(&StatErrQueueParseError, 1)
	}
}

func opQueueParseError(data []byte) {
	select {
	case chanParseError <- data:
		// No op, it was submitted to the channel
	default:
		// Channel is full, so handle synchronously
		atomic.AddUint64(&StatQueueFullParseError, 1)
		_opQueueParseError(data)
	}
}

func _opQueueAtypical(data []byte) {
	mc := (*Config)(atomic.LoadPointer(&MainConfig))
	if mc.QueueAtypical == nil {
		return
	}
	sqsc := sqs.New(sess, cfg.WithRegion(mc.QueueAtypical[0]))

	input := &sqs.SendMessageInput{
		QueueUrl:    aws.String(mc.QueueAtypical[1]),
		MessageBody: aws.String(base64.StdEncoding.EncodeToString(data)),
	}

	if _, err := sqsc.SendMessage(input); err != nil {
		atomic.AddUint64(&StatErrQueueAtypical, 1)
	}
}

func opQueueAtypical(data []byte) {
	select {
	case chanAtypical <- data:
		// No op, it was submitted to the channel
	default:
		// Channel is full, so handle synchronously
		atomic.AddUint64(&StatQueueFullAtypical, 1)
		_opQueueAtypical(data)
	}
}

func opStorePrimary(r io.ReadSeeker, key string) error {
	// TODO: move this into a ticker:
	mc := (*Config)(atomic.LoadPointer(&MainConfig))
	s3c := s3.New(sess, cfg.WithRegion(mc.StoragePrimary[0]))

	r.Seek(0, 0)
	inp := &s3.PutObjectInput{
		Body:   r,
		Bucket: aws.String(mc.StoragePrimary[1]),
		Key:    aws.String(key),
	}

	_, err := s3c.PutObject(inp)
	return err
}

func opStoreSecondary(r io.ReadSeeker, key string) error {
	// TODO: move this into a ticker:
	mc := (*Config)(atomic.LoadPointer(&MainConfig))
	if mc.StorageSecondary == nil {
		return NotConfiguredError
	}
	s3c := s3.New(sess, cfg.WithRegion(mc.StorageSecondary[0]))

	r.Seek(0, 0)
	inp := &s3.PutObjectInput{
		Body:   r,
		Bucket: aws.String(mc.StorageSecondary[1]),
		Key:    aws.String(key),
	}

	_, err := s3c.PutObject(inp)
	return err
}
