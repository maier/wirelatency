// Copyright © 2016 Circonus, Inc. <support@circonus.com>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//

package wirelatency

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/golang/snappy"
)

var debugKafka = flag.Bool("debugKafka", false, "Debug kafka reassembly")

// type kafkaConfig struct {
// 	dummy int
// }

func kafkaConfigParser(c *string) interface{} {
	return nil
	// config := kafkaConfig{}
	// return config
}

const (
	kafkaAPIProduceRequest          = int16(0)
	kafkaAPIFetchRequest            = int16(1)
	kafkaAPIOffsetRequest           = int16(2)
	kafkaAPIMetadataRequest         = int16(3)
	kafkaAPIControl4                = int16(4)
	kafkaAPIControl5                = int16(5)
	kafkaAPIControl6                = int16(6)
	kafkaAPIControl7                = int16(7)
	kafkaAPIOffsetCommitRequest     = int16(8)
	kafkaAPIOffsetFetchRequest      = int16(9)
	kafkaAPIGroupCoordinatorRequest = int16(10)
	kafkaAPIJoinGroupRequest        = int16(11)
	kafkaAPIHeartbeatRequest        = int16(12)
	kafkaAPILeaveGroupRequest       = int16(13)
	kafkaAPISyncGroupRequest        = int16(14)
	kafkaAPIDescribeGroupsRequest   = int16(15)
	kafkaAPIListGroupsRequest       = int16(16)

	// currently unused
	// kafka_NoError                          = int16(0)
	// kafka_Unknown                          = int16(-1)
	// kafka_OffsetOutOfRange                 = int16(1)
	// kafka_InvalidMessage                   = int16(2)
	// kafka_UnknownTopicOrPartition          = int16(3)
	// kafka_InvalidMessageSize               = int16(4)
	// kafka_LeaderNotAvailable               = int16(5)
	// kafka_NotLeaderForPartition            = int16(6)
	// kafka_RequestTimedOut                  = int16(7)
	// kafka_BrokerNotAvailable               = int16(8)
	// kafka_ReplicaNotAvailable              = int16(9)
	// kafka_MessageSizeTooLarge              = int16(10)
	// kafka_StaleControllerEpochCode         = int16(11)
	// kafka_OffsetMetadataTooLargeCode       = int16(12)
	// kafka_GroupLoadInProgressCode          = int16(14)
	// kafka_GroupCoordinatorNotAvailableCode = int16(15)
	// kafka_NotCoordinatorForGroupCode       = int16(16)
	// kafka_InvalidTopicCode                 = int16(17)
	// kafka_RecordListTooLargeCode           = int16(18)
	// kafka_NotEnoughReplicasCode            = int16(19)
	// kafka_NotEnoughReplicasAfterAppendCode = int16(20)
	// kafka_InvalidRequiredAcksCode          = int16(21)
	// kafka_IllegalGenerationCode            = int16(22)
	// kafka_InconsistentGroupProtocolCode    = int16(23)
	// kafka_InvalidGroupIdCode               = int16(24)
	// kafka_UnknownMemberIdCode              = int16(25)
	// kafka_InvalidSessionTimeoutCode        = int16(26)
	// kafka_RebalanceInProgressCode          = int16(27)
	// kafka_InvalidCommitOffsetSizeCode      = int16(28)
	// kafka_TopicAuthorizationFailedCode     = int16(29)
	// kafka_GroupAuthorizationFailedCode     = int16(30)
	// kafka_ClusterAuthorizationFailedCode   = int16(31)

	kafkaRetainedPayloadSize = int(1024)
)

type kafkaMessage struct {
	parentCompression int8
	offset            int64
	// length             int32
	crc        int32
	magicByte  int8
	attributes int8
	timestamp  time.Time
	key        []byte
	value      []byte

	valueLen int
}
type kafkaPartitionSet struct {
	partition int32
	recordSet []byte
	messages  []kafkaMessage
}
type kafkaProduceReqPartition struct {
	pset kafkaPartitionSet
}
type kafkaProduceReqTopic struct {
	topic      string
	partitions []kafkaProduceReqPartition
}
type kafkaProduceRequest struct {
	requiredacks int16
	timeout      int32
	topics       []kafkaProduceReqTopic
}
type kafkaResponseFrame struct {
	correlationid int32
}
type kafkaFetchPartition struct {
	pset          kafkaPartitionSet
	errorCode     int16
	highWatermark int64
}
type kafkaFetchTopic struct {
	topic      string
	partitions []kafkaFetchPartition
}
type kafkaFetchResponse struct {
	throttleTimeMS int32
	topics         []kafkaFetchTopic
}

type kafkaProducePartition struct {
	partition int32
	errorCode int16
	offset    int64
	timestamp time.Time
}
type kafkaProduceTopic struct {
	topic      string
	partitions []kafkaProducePartition
}
type kafkaProduceResponse struct {
	throttleTimeMS int32
	topics         []kafkaProduceTopic
}

var globalKafkaFetch kafkaFetchResponse
var globalKafkaProduce kafkaProduceResponse

type kafkaRequestFrame struct {
	apikey        int16
	apiversion    int16
	correlationid int32
	clientid      string
}
type kafkaFrame struct {
	inbound  bool
	complete bool
	soFar    int

	request         kafkaRequestFrame
	response        kafkaResponseFrame
	produceRequest  *kafkaProduceRequest
	produceResponse *kafkaProduceResponse
	fetchResponse   *kafkaFetchResponse

	length      int32
	lengthBytes [4]byte
	payload     []byte
	truncated   bool // don't use the payload, it's not all there

	//
	timestamp time.Time
	latency   time.Duration
	// response_bytes int
}
type kafkaParser struct {
	factory       *kafkaParserFactory
	stream        map[int32]*kafkaFrame
	requestFrame  kafkaFrame
	responseFrame kafkaFrame
}

func kafkaFrameAPIName(code int16) (string, bool) {
	switch code {
	case kafkaAPIProduceRequest:
		return "ProduceRequest", true
	case kafkaAPIFetchRequest:
		return "FetchRequest", true
	case kafkaAPIOffsetRequest:
		return "OffsetRequest", true
	case kafkaAPIMetadataRequest:
		return "MetadataRequest", true
	case kafkaAPIControl4:
		return "Control4", true
	case kafkaAPIControl5:
		return "Control5", true
	case kafkaAPIControl6:
		return "Control6", true
	case kafkaAPIControl7:
		return "Control7", true
	case kafkaAPIOffsetCommitRequest:
		return "OffsetCommitRequest", true
	case kafkaAPIOffsetFetchRequest:
		return "OffsetFetchRequest", true
	case kafkaAPIGroupCoordinatorRequest:
		return "GroupCoordinatorRequest", true
	case kafkaAPIJoinGroupRequest:
		return "JoinGroupRequest", true
	case kafkaAPIHeartbeatRequest:
		return "HeartbeatRequest", true
	case kafkaAPILeaveGroupRequest:
		return "LeaveGroupRequest", true
	case kafkaAPISyncGroupRequest:
		return "SyncGroupRequest", true
	case kafkaAPIDescribeGroupsRequest:
		return "DescribeGroupsRequest", true
	case kafkaAPIListGroupsRequest:
		return "ListGroupsRequest", true
	}
	return fmt.Sprintf("unknown:%d", code), false
}
func (f *kafkaFrame) APIName() string {
	if f.inbound {
		name, _ := kafkaFrameAPIName(f.request.apikey)
		return name
	}
	return "Response"
}
func (f *kafkaFrame) copy() *kafkaFrame {
	newFrame := *f
	newFrame.payload = nil
	return &newFrame
}
func (p *kafkaParser) reportPset(f *kafkaFrame, pset *kafkaPartitionSet, topic string, partition int32, now time.Time) int {
	numMsgs := 0
	if pset.messages != nil {
		for _, m := range pset.messages {
			numMsgs++
			if f.request.apiversion > 0 && (f.produceRequest == nil || f.produceRequest.requiredacks != 0) {
				mlat := now.Sub(m.timestamp)
				wlTrackFloat64("seconds", mlat.Seconds(), f.APIName()+"`_aggregate`message`latency")
				wlTrackFloat64("seconds", mlat.Seconds(), f.APIName()+"`"+topic+"`message`latency")
			}
			if m.value != nil {
				wlTrackInt64("bytes", int64(m.valueLen), f.APIName()+"`_aggregate`message`size")
				wlTrackInt64("bytes", int64(m.valueLen), f.APIName()+"`"+topic+"`message`size")
			}
		}
	}
	return numMsgs
}
func (p *kafkaParser) report(stream *tcpTwoWayStream, f *kafkaFrame, now time.Time) {
	latency := &f.latency
	if f.request.apikey == kafkaAPIProduceRequest &&
		f.produceRequest != nil &&
		f.produceRequest.requiredacks == 0 {
		latency = nil
		numMsgs := 0
		for _, topic := range f.produceRequest.topics {
			pMsgs := 0
			for _, part := range topic.partitions {
				pMsgs += p.reportPset(f, &part.pset, topic.topic, part.pset.partition, now)
			}
			wlTrackInt64("messages", int64(pMsgs), f.APIName()+"`"+topic.topic+"`messages")
			wlTrackInt64("bytes", int64(f.length), f.APIName()+"`"+topic.topic+"`bytes")
			numMsgs += pMsgs
		}
		wlTrackInt64("messages", int64(numMsgs), f.APIName()+"`_aggregate`messages")
		wlTrackInt64("bytes", int64(f.length), f.APIName()+"`_aggregate`bytes")
	}
	if latency != nil {
		wlTrackFloat64("seconds", float64(*latency)/1000000000.0, f.APIName()+"`latency")
	}
	if f.produceResponse != nil || f.fetchResponse != nil {
		numMsgs := 0
		if f.produceResponse != nil && f.produceRequest != nil {
			for _, topic := range f.produceResponse.topics {
				pMsgs := 0
				var rparts []kafkaProduceReqPartition
				for _, rtopic := range f.produceRequest.topics {
					if topic.topic == rtopic.topic {
						rparts = rtopic.partitions
					}
				}
				for _, part := range topic.partitions {
					for _, rpart := range rparts {
						if part.partition == rpart.pset.partition {
							pMsgs += p.reportPset(f, &rpart.pset, topic.topic, part.partition, now)
						}
					}
				}
				wlTrackInt64("messages", int64(pMsgs), f.APIName()+"`"+topic.topic+"`messages")
				wlTrackInt64("bytes", int64(f.length), f.APIName()+"`"+topic.topic+"`bytes")
				numMsgs += pMsgs
			}
			if f.request.apiversion > 0 {
				wlTrackFloat64("seconds", float64(f.produceResponse.throttleTimeMS)/1000.0, f.APIName()+"`throttle_time")
			}
		} else if f.fetchResponse != nil {
			for _, topic := range f.fetchResponse.topics {
				pMsgs := 0
				for _, part := range topic.partitions {
					pMsgs += p.reportPset(f, &part.pset, topic.topic, part.pset.partition, now)
				}
				wlTrackInt64("messages", int64(pMsgs), f.APIName()+"`"+topic.topic+"`messages")
				wlTrackInt64("bytes", int64(f.length), f.APIName()+"`"+topic.topic+"`bytes")
				numMsgs += pMsgs
			}
		}
		wlTrackInt64("messages", int64(numMsgs), f.APIName()+"`_aggregate`messages")
		wlTrackInt64("bytes", int64(f.length), f.APIName()+"`_aggregate`bytes")
	}
}

var snappyJavaMagic = []byte("\x82SNAPPY\x00")

func (p *kafkaParser) expandMessages(stream *tcpTwoWayStream, in []kafkaMessage, apiversion int16, pc int8, data []byte) []kafkaMessage {
	if in == nil {
		in = make([]kafkaMessage, 0, 10)
	}
	used := 0
	for used < len(data) {
		m := kafkaMessage{}
		m.parentCompression = pc
		if m.offset, used = kafkaReadInt64(data, used); used < 0 {
			stream.factory.Error("bad_packet")
			return in
		}
		mLen := int32(0)
		if mLen, used = kafkaReadInt32(data, used); used < 0 || mLen < 1 {
			stream.factory.Error("bad_packet")
			return in
		}
		expectedUsed := used + int(mLen)
		if m.crc, used = kafkaReadInt32(data, used); used < 0 {
			stream.factory.Error("bad_packet")
			return in
		}
		if m.magicByte, used = kafkaReadInt8(data, used); used < 0 {
			stream.factory.Error("bad_packet")
			return in
		}
		if m.attributes, used = kafkaReadInt8(data, used); used < 0 {
			stream.factory.Error("bad_packet")
			return in
		}
		if apiversion > 0 {
			var timestamp int64
			if timestamp, used = kafkaReadInt64(data, used); used < 0 {
				stream.factory.Error("bad_packet")
				return in
			}
			m.timestamp = time.Unix(timestamp/1000, (timestamp%1000)*1000000)
		}
		if m.key, used = kafkaReadBytes(data, used); used < 0 {
			stream.factory.Error("bad_packet")
			return in
		}
		if m.value, used = kafkaReadBytes(data, used); used < 0 {
			stream.factory.Error("bad_packet")
			return in
		}
		m.valueLen = len(m.value)
		switch m.attributes & 0x7 {
		case 0:
			in = append(in, m)
		case 1: //gzip
			if compressed, err := gzip.NewReader(bytes.NewReader(m.value)); err == nil {
				defer compressed.Close()
				if data, rerr := ioutil.ReadAll(compressed); rerr == nil {
					in = p.expandMessages(stream, in, apiversion, 2, data)
				} else {
					stream.factory.Error("bad_packet:gzip")
				}
			}
		case 2: //snappy
			if !bytes.HasPrefix(m.value, snappyJavaMagic) {
				if data, err := snappy.Decode(nil, m.value); err == nil {
					in = p.expandMessages(stream, in, apiversion, 2, data)
				} else {
					stream.factory.Error("bad_packet:snappy")
					if *debugKafka {
						log.Printf("[DEBUG] snappy failed: %v", err)
					}
				}
			} else if binary.BigEndian.Uint32(m.value[8:12]) == 1 {
				data := make([]byte, 0, len(m.value))
				var chunk []byte
				for i := 16; i < len(m.value); {
					n := int(binary.BigEndian.Uint32(m.value[i : i+4]))
					i += 4
					chunk, err := snappy.Decode(chunk, m.value[i:i+n])
					if err != nil {
						stream.factory.Error("bad_packet:snappy")
						data = nil
						break
					}
					i += n
					if data != nil {
						data = append(data, chunk...)
					}
				}
				if data != nil {
					in = p.expandMessages(stream, in, apiversion, 2, data)
				}
			}
		case 3: //lz4
			// todo golang lz4 implementations are "meh" and this is actually lz4f
		}

		if used != expectedUsed {
			stream.factory.Error("bad_packet")
			if *debugKafka {
				log.Printf("[DEBUG] corrupted message?")
			}
			used = expectedUsed
		}
	}
	return in
}
func (p *kafkaParser) validateIn(stream *tcpTwoWayStream, f *kafkaFrame) (bool, bool) {
	// parse our request header
	used := 0
	if f.request.apikey, used = kafkaReadInt16(f.payload, used); used < 0 {
		stream.factory.Error("bad_packet")
		return false, false
	}
	if f.request.apiversion, used = kafkaReadInt16(f.payload, used); used < 0 {
		stream.factory.Error("bad_packet")
		return false, false
	}
	if f.request.correlationid, used = kafkaReadInt32(f.payload, used); used < 0 {
		stream.factory.Error("bad_packet")
		return false, false
	}
	if f.request.clientid, used = kafkaReadString(f.payload, used); used < 0 {
		stream.factory.Error("bad_packet")
		return false, false
	}

	expectResponse := true
	_, valid := kafkaFrameAPIName(f.request.apikey)
	// if it is a publish request with ack of 0, there will be no response
	if f.request.apikey == kafkaAPIProduceRequest {
		pr := kafkaProduceRequest{}
		if pr.requiredacks, used = kafkaReadInt16(f.payload, used); used < 0 {
			stream.factory.Error("bad_packet")
			return false, false
		}
		if pr.timeout, used = kafkaReadInt32(f.payload, used); used < 0 {
			stream.factory.Error("bad_packet")
			return false, false
		}
		var numTopics int32
		if numTopics, used = kafkaReadInt32(f.payload, used); used < 0 {
			stream.factory.Error("bad_packet")
			return false, false
		}
		pr.topics = make([]kafkaProduceReqTopic, numTopics)
		for i := int32(0); i < numTopics; i++ {
			if pr.topics[i].topic, used = kafkaReadString(f.payload, used); used < 0 {
				stream.factory.Error("bad_packet")
				return false, false
			}
			var numPartitions int32
			if numPartitions, used = kafkaReadInt32(f.payload, used); used < 0 {
				stream.factory.Error("bad_packet")
				return false, false
			}
			pr.topics[i].partitions = make([]kafkaProduceReqPartition, numPartitions)
			for j := int32(0); j < numPartitions; j++ {
				part := &pr.topics[i].partitions[j]
				pset := &part.pset
				if pset.partition, used = kafkaReadInt32(f.payload, used); used < 0 {
					stream.factory.Error("bad_packet")
					return false, false
				}
				if pset.recordSet, used = kafkaReadBytes(f.payload, used); used < 0 {
					stream.factory.Error("bad_packet")
					return false, false
				}
				pset.messages = p.expandMessages(stream, pset.messages, f.request.apiversion, 0, pset.recordSet)
				// Zip through the messages and set their timestamps to the frame's timestamp
				// we do this b/c we care about produce latencies, not timestamp latencies
				for _, message := range pset.messages {
					message.timestamp = f.timestamp
				}
			}
		}
		if pr.requiredacks == 0 {
			expectResponse = false
			p.report(stream, f, f.timestamp)
		}
		f.produceRequest = &pr
	}
	return valid, expectResponse
}
func (p *kafkaParser) validateOut(stream *tcpTwoWayStream, f *kafkaFrame) bool {
	used := 0
	if f.response.correlationid, used = kafkaReadInt32(f.payload, used); used < 0 {
		stream.factory.Error("bad_packet")
		return false
	}
	req, ok := p.stream[f.response.correlationid]
	if !ok {
		stream.factory.Error("uncorrelated_response")
		return false
	}
	switch req.request.apikey {
	case kafkaAPIFetchRequest:
		globalKafkaFetch.throttleTimeMS = -1
		if req.request.apiversion > 0 {
			globalKafkaFetch.throttleTimeMS, used = kafkaReadInt32(f.payload, used)
			if used < 0 {
				stream.factory.Error("bad_packet")
				return false
			}
		}
		var numTopics int32
		numTopics, used = kafkaReadInt32(f.payload, used)
		if used < 0 {
			stream.factory.Error("bad_packet")
			return false
		}
		globalKafkaFetch.topics = make([]kafkaFetchTopic, numTopics)
		for i := int32(0); i < numTopics; i++ {
			var numPartitions int32
			if globalKafkaFetch.topics[i].topic, used = kafkaReadString(f.payload, used); used < 0 {
				stream.factory.Error("bad_packet")
				return false
			}
			if numPartitions, used = kafkaReadInt32(f.payload, used); used < 0 {
				stream.factory.Error("bad_packet")
				return false
			}
			globalKafkaFetch.topics[i].partitions = make([]kafkaFetchPartition, numPartitions)
			for j := int32(0); j < numPartitions; j++ {
				part := &globalKafkaFetch.topics[i].partitions[j]
				pset := &part.pset
				if pset.partition, used = kafkaReadInt32(f.payload, used); used < 0 {
					stream.factory.Error("bad_packet")
					return false
				}
				if part.errorCode, used = kafkaReadInt16(f.payload, used); used < 0 {
					stream.factory.Error("bad_packet")
					return false
				}
				if part.highWatermark, used = kafkaReadInt64(f.payload, used); used < 0 {
					stream.factory.Error("bad_packet")
					return false
				}
				if pset.recordSet, used = kafkaReadBytes(f.payload, used); used < 0 {
					stream.factory.Error("bad_packet")
					return false
				}
				pset.messages = p.expandMessages(stream, pset.messages, req.request.apiversion, 0, pset.recordSet)
			}
		}
		req.fetchResponse = &globalKafkaFetch
	case kafkaAPIProduceRequest:
		globalKafkaProduce.throttleTimeMS = -1
		var numTopics int32
		if numTopics, used = kafkaReadInt32(f.payload, used); used < 0 {
			stream.factory.Error("bad_packet")
			return false
		}
		globalKafkaProduce.topics = make([]kafkaProduceTopic, numTopics)
		for i := int32(0); i < numTopics; i++ {
			var numPartitions int32
			if globalKafkaProduce.topics[i].topic, used = kafkaReadString(f.payload, used); used < 0 {
				stream.factory.Error("bad_packet")
				return false
			}
			if numPartitions, used = kafkaReadInt32(f.payload, used); used < 0 {
				stream.factory.Error("bad_packet")
				return false
			}
			globalKafkaProduce.topics[i].partitions = make([]kafkaProducePartition, numPartitions)
			for p := int32(0); p < numPartitions; p++ {
				part := &globalKafkaProduce.topics[i].partitions[p]
				if part.partition, used = kafkaReadInt32(f.payload, used); used < 0 {
					stream.factory.Error("bad_packet")
					return false
				}
				if part.errorCode, used = kafkaReadInt16(f.payload, used); used < 0 {
					stream.factory.Error("bad_packet")
					return false
				}
				if part.offset, used = kafkaReadInt64(f.payload, used); used < 0 {
					stream.factory.Error("bad_packet")
					return false
				}
				if req.request.apiversion > 1 {
					var timestamp int64
					if timestamp, used = kafkaReadInt64(f.payload, used); used < 0 {
						stream.factory.Error("bad_packet")
						return false
					}
					if timestamp == -1 {
						part.timestamp = time.Time{}
					} else {
						part.timestamp = time.Unix(timestamp/1000, (timestamp%1000)*1000000)
					}
				}
			}
		}
		if req.request.apiversion > 0 {
			if globalKafkaFetch.throttleTimeMS, used = kafkaReadInt32(f.payload, used); used < 0 {
				stream.factory.Error("bad_packet")
				return false
			}
		}
		req.produceResponse = &globalKafkaProduce
	}
	return true
}
func (f *kafkaFrame) init() {
	f.complete = false
	f.soFar = 0
	f.request.apikey = -1
	f.request.apiversion = -1
	f.request.correlationid = -1
	f.request.clientid = ""
	f.fetchResponse = nil
	f.produceRequest = nil
	f.produceResponse = nil
	f.timestamp = time.Time{}
	f.latency = 0
	f.length = 0
	f.truncated = false
	if f.payload == nil || cap(f.payload) != kafkaRetainedPayloadSize {
		f.payload = make([]byte, 0, kafkaRetainedPayloadSize)
	}
	f.payload = f.payload[:0]
}

// Takes "more" data in and attempts to complete the frame
// returns complete if the frame is complete. Always returns
// the number of bytes of the passed data used.  used should
// be the entire data size if frame is incomplete
// If things go off the rails unrecoverably, used = -1 is returned
func (f *kafkaFrame) fillFrame(seen time.Time, data []byte) (complete bool, used int) {
	if len(data) < 1 {
		return false, 0
	}
	if f.soFar == 0 {
		f.timestamp = seen
	}
	// Next four bytes are the length (inclusive of the four bytes?!)
	for ; used < len(data) && f.soFar < 4; f.soFar, used = f.soFar+1, used+1 {
		f.lengthBytes[f.soFar] = data[used]
		if f.soFar == 3 {
			f.length = int32(binary.BigEndian.Uint32(f.lengthBytes[:]))
		}
	}
	if f.soFar < 4 {
		return false, used
	}

	// Now we read in the legnth
	remaining := f.length - (int32(f.soFar) - 4)
	toAppend := remaining // how much we're actually reading
	if int32(len(data)-used) < remaining {
		// not complete
		toAppend = int32(len(data) - used)
	}
	cappedAppend := toAppend // how much we're actually writing
	if len(f.payload)+int(toAppend) > cap(f.payload) {
		cappedAppend = int32(cap(f.payload) - len(f.payload))
		f.truncated = true
	}
	if cappedAppend > 0 {
		f.payload = append(f.payload, data[used:(used+int(cappedAppend))]...)
	}
	used += int(toAppend)
	f.soFar += int(toAppend)
	if remaining == toAppend {
		f.complete = true
		if *debugKafka {
			log.Printf("[DEBUG] frame completed")
		}
		return true, used
	}
	if *debugKafka {
		log.Printf("[DEBUG] frame pending")
	}
	return false, used
}

// unused
// func (p *kafka_Parser) flushStream() {
// 	p.stream = make(map[int32]*kafka_frame)
// }

func kafkaReadInt8(data []byte, used int) (int8, int) {
	if len(data) > used+0 {
		return int8(data[used]), used + 1
	}
	return int8(-1), -1
}
func kafkaReadInt16(data []byte, used int) (int16, int) {
	if len(data) > used+1 {
		return int16(binary.BigEndian.Uint16(data[used:])), used + 2
	}
	return int16(-1), -1
}
func kafkaReadInt32(data []byte, used int) (int32, int) {
	if len(data) > used+3 {
		return int32(binary.BigEndian.Uint32(data[used:])), used + 4
	}
	return int32(-1), -1
}
func kafkaReadInt64(data []byte, used int) (int64, int) {
	if len(data) > used+7 {
		return int64(binary.BigEndian.Uint64(data[used:])), used + 8
	}
	return int64(-1), -1
}
func kafkaReadString(data []byte, used int) (string, int) {
	var slen int16
	slen, used = kafkaReadInt16(data, used)
	if used < 0 || len(data) < used+int(slen) {
		return "", -1
	}
	return string(data[used : used+int(slen)]), used + int(slen)
}
func kafkaReadBytes(data []byte, used int) ([]byte, int) {
	slen, used := kafkaReadInt32(data, used)
	if used < 0 {
		return nil, -1
	}
	// -1 is a nil string
	if slen == -1 {
		return nil, used
	}

	if len(data) < used+int(slen) {
		return nil, -1
	}
	return data[used : used+int(slen)], used + int(slen)
}

func (p *kafkaParser) reset() {
	p.stream = make(map[int32]*kafkaFrame)
	p.requestFrame.init()
	p.responseFrame.init()
}
func (p *kafkaParser) InBytes(stream *tcpTwoWayStream, seen time.Time, data []byte) bool {
	// build a request
	for {
		if len(data) == 0 {
			return true
		}

		complete, used := p.requestFrame.fillFrame(seen, data)
		if !complete {
			return true
		}
		if used < 0 {
			if *debugKafka {
				log.Printf("[DEBUG] <- BAD READ IN: %v", used)
			}
			p.reset()
			return true
		}
		if complete {
			f := &p.requestFrame
			valid, expectResponse := p.validateIn(stream, f)
			if !valid {
				if *debugKafka {
					log.Printf("[DEBUG] <- BAD FRAME: %v", p.requestFrame.APIName())
				}
				p.reset()
				return true
			}
			if expectResponse {
				p.stream[f.request.correlationid] = f.copy()
			} else {
				p.report(stream, f, seen)
			}
			data = data[used:]
			p.requestFrame.init()
		}
		// if complete, used := p.requestFrame.fillFrame(seen, data); complete {
		// 	f := &p.requestFrame
		// 	valid, expectResponse := p.validateIn(stream, f)
		// 	if !valid {
		// 		if *debugKafka {
		// 			log.Printf("[DEBUG] <- BAD FRAME: %v", p.requestFrame.APIName())
		// 		}
		// 		p.reset()
		// 		return true
		// 	}
		// 	if expectResponse {
		// 		p.stream[f.request.correlationid] = f.copy()
		// 	} else {
		// 		p.report(stream, f, seen)
		// 	}
		// 	data = data[used:]
		// 	p.requestFrame.init()
		// } else if used < 0 {
		// 	if *debugKafka {
		// 		log.Printf("[DEBUG] <- BAD READ IN: %v", used)
		// 	}
		// 	p.reset()
		// 	return true
		// } else if !complete {
		// 	return true
		// }
	}
}
func (p *kafkaParser) OutBytes(stream *tcpTwoWayStream, seen time.Time, data []byte) bool {
	for {
		if len(data) == 0 {
			return true
		}

		complete, used := p.responseFrame.fillFrame(seen, data)
		if !complete {
			return true
		}
		if used < 0 {
			if *debugKafka {
				log.Printf("[DEBUG] -> BAD READ OUT: %v", used)
			}
			p.reset()
			return true
		}
		if complete {
			f := &p.responseFrame
			if !p.validateOut(stream, f) {
				if *debugKafka {
					log.Printf("[DEBUG] -> BAD FRAME: %v", p.requestFrame.APIName())
				}
				p.reset()
				return true
			}
			if *debugKafka {
				log.Printf("[DEBUG] -> %v [%v]", f.APIName(), used)
			}
			if req, ok := p.stream[f.response.correlationid]; ok {
				req.latency = seen.Sub(req.timestamp)
				delete(p.stream, f.response.correlationid)
				if *debugKafka {
					log.Printf("[DEBUG] %v -> %v\nREQUEST: %+v\n", req.APIName(), seen.Sub(req.timestamp), req)
				}
				p.report(stream, req, seen)
			}

			data = data[used:]
			p.responseFrame.init()
		}
	}
}
func (p *kafkaParser) ManageIn(stream *tcpTwoWayStream) {
	panic("kafka wirelatency parser is not async")
}
func (p *kafkaParser) ManageOut(stream *tcpTwoWayStream) {
	panic("kafka wirelatency parser is not async")
}

type kafkaParserFactory struct {
	// parsed map[uint16]string
}

func (f *kafkaParserFactory) New() TCPProtocolInterpreter {
	p := kafkaParser{}
	p.factory = f
	p.requestFrame.inbound = true
	p.reset()
	return &p
}
func init() {
	factory := &kafkaParserFactory{}
	kafkaProt := &TCPProtocol{
		name:        "kafka",
		defaultPort: 9093,
		inFlight:    true,
		Config:      kafkaConfigParser,
	}
	kafkaProt.interpFactory = factory
	RegisterTCPProtocol(kafkaProt)
}
