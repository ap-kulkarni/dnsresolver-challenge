package dnsresolvr

import (
	"crypto/rand"
	bytereader "dnsresolvr/internal/pkg"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
)

type OpCode uint16

const (
	StandardQuery OpCode = iota
	InverseQuery
	StatusQuery
)

type ResponseCode uint16

const (
	NoError ResponseCode = iota
	FormatError
	ServerFailure
	NameError
	NotImplemented
	Refused
)

type MessageType uint16

const (
	A MessageType = iota + 1
	NS
	MD
	MF
	CNAME
	SOA
	MB
	MG
	MR
	NULL
	WKS
	PTR
	HINFO
	MINFO
	MX
	TXT
	AXFR  = 252
	MAILB = 253
	MAILA = 254
)

type MessageClass uint16

const (
	IN MessageClass = iota + 1
	CS
	CH
	HS
	ANY = 255
)

type DnsHeader struct {
	Id                          uint16
	IsResponse                  bool
	Opcode                      OpCode
	IsAuthoritativeAnswer       bool
	IsTruncatedMessage          bool
	IsRecursionDesired          bool
	IsRecursionSupportAvailable bool
	ResponseCode                ResponseCode
	QuestionCount               uint16
	AnswerCount                 uint16
	NameServerRecordsCount      uint16
	AdditionalRecordsCount      uint16
}

func (h DnsHeader) GetBytes() []byte {
	var headerBytes []byte

	headerBytes = append(headerBytes, convertUint16ToBytesArray(h.Id)...)
	headerBytes = append(headerBytes, h.getHeaderMetadata()...)
	headerBytes = append(headerBytes, convertUint16ToBytesArray(h.QuestionCount)...)
	headerBytes = append(headerBytes, convertUint16ToBytesArray(h.AnswerCount)...)
	headerBytes = append(headerBytes, convertUint16ToBytesArray(h.NameServerRecordsCount)...)
	headerBytes = append(headerBytes, convertUint16ToBytesArray(h.AdditionalRecordsCount)...)
	return headerBytes
}

func (h DnsHeader) getHeaderMetadata() []byte {
	headerMeta := uint16(0)
	if h.IsResponse {
		headerMeta += 1 << 15
	}
	headerMeta += uint16(h.Opcode) << 14
	if h.IsAuthoritativeAnswer {
		headerMeta += 1 << 10
	}
	if h.IsTruncatedMessage {
		headerMeta += 1 << 9
	}
	if h.IsRecursionDesired {
		headerMeta += 1 << 8
	}
	if h.IsRecursionSupportAvailable {
		headerMeta += 1 << 7
	}
	headerMeta += uint16(h.ResponseCode)
	return convertUint16ToBytesArray(headerMeta)
}

type DnsQueryQuestion struct {
	Qname  []byte
	Qtype  MessageType
	Qclass MessageClass
}

func (q DnsQueryQuestion) GetBytes() []byte {
	var questionBytes []byte
	questionBytes = append(questionBytes, q.Qname...)
	questionBytes = append(questionBytes, convertUint16ToBytesArray(uint16(q.Qtype))...)
	questionBytes = append(questionBytes, convertUint16ToBytesArray(uint16(q.Qclass))...)
	return questionBytes
}

type DnsQuery struct {
	Header    DnsHeader
	Questions []DnsQueryQuestion
}

func (q DnsQuery) GetBytes() []byte {
	var queryBytes []byte
	queryBytes = append(queryBytes, q.Header.GetBytes()...)
	for i := 0; i < len(q.Questions); i++ {
		queryQuestion := q.Questions[i]
		queryBytes = append(queryBytes, queryQuestion.GetBytes()...)
	}
	return queryBytes
}

// Converts domain name string to qname format. e.g "www.google.com" gets converted to
// "3www6google3com0"
func getDomainNameInQnameFormat(domainName string) []byte {
	nameParts := strings.Split(domainName, ".")
	var QnameBytes []byte
	for i := 0; i < len(nameParts); i++ {
		namePart := nameParts[i]
		QnameBytes = append(QnameBytes, uint8(len(namePart)))
		QnameBytes = append(QnameBytes, []byte(namePart)...)
	}
	QnameBytes = append(QnameBytes, uint8(0))
	return QnameBytes
}

func generateDnsQuery(domainName string) *DnsQuery {
	queryHeader := &DnsHeader{}
	queryHeader.Id = getRandomUint16()
	queryHeader.Opcode = StandardQuery
	queryHeader.QuestionCount = 1
	queryHeader.IsRecursionDesired = true
	queryQuestion := &DnsQueryQuestion{}
	queryQuestion.Qname = getDomainNameInQnameFormat(domainName)
	queryQuestion.Qclass = IN
	queryQuestion.Qtype = A
	query := &DnsQuery{}
	query.Header = *queryHeader
	query.Questions = []DnsQueryQuestion{*queryQuestion}
	return query
}

func getRandomUint16() uint16 {
	randInt, err := rand.Int(rand.Reader, big.NewInt(65535))
	if err != nil {
		os.Exit(2)
	}
	return uint16(randInt.Uint64())
}

func convertUint16ToBytesArray(number uint16) []byte {
	numBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(numBytes, number)
	return numBytes
}

func getUint16FromBytes(bytesToConvert []byte) uint16 {
	return binary.BigEndian.Uint16(bytesToConvert)
}

func queryDns(domainName string) ([]byte, error) {
	dnsQuery := generateDnsQuery(domainName)
	addr, err := net.ResolveUDPAddr("udp", "8.8.8.8:53")
	if err != nil {
		fmt.Println("Error occurred while resolving address for DNS. ", err)
		os.Exit(2)
	}
	udp, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		fmt.Println("Error occurred while initiating connection with DNS. ", err)
		os.Exit(2)
	}
	defer func(udp *net.UDPConn) {
		_ = udp.Close()
	}(udp)
	_, connErr := udp.Write(dnsQuery.GetBytes())
	if connErr != nil {
		fmt.Println("Error sending request to DNS.", connErr)
		os.Exit(2)
	}
	response := make([]byte, 512)
	responseLength, readErr := udp.Read(response)
	if readErr != nil {
		return nil, readErr
	}
	udpResponse := make([]byte, responseLength)
	copy(udpResponse, response)
	return udpResponse, nil
}

func parseResponse(response []byte) {
	responseReader := bytereader.NewByteReader(response)
	dnsHeader := &DnsHeader{}
	responseId, err := responseReader.ReadUint16()
	if err != nil {
		fmt.Println("Error parsing response ID: ", err)
	}
	dnsHeader.Id = responseId
	headerMeta, _ := responseReader.ReadUint16()
	_ = populateDnsHeaderWithMetadata(headerMeta, dnsHeader)
	dnsHeader.QuestionCount, _ = responseReader.ReadUint16()
	dnsHeader.AnswerCount, _ = responseReader.ReadUint16()
	dnsHeader.NameServerRecordsCount, _ = responseReader.ReadUint16()
	dnsHeader.AdditionalRecordsCount, _ = responseReader.ReadUint16()
	fmt.Println("Response Id: ", dnsHeader.Id)
	fmt.Println("Is Response", dnsHeader.IsResponse)
	fmt.Println("Is authoritative", dnsHeader.IsAuthoritativeAnswer)
	fmt.Println("Is truncated: ", dnsHeader.IsTruncatedMessage)
	fmt.Println("Question Count: ", dnsHeader.QuestionCount)
	fmt.Println("Answer Count: ", dnsHeader.AnswerCount)
	//parseAnswersFromResponse(response[12:])
}

func readDomainFromResponse(responseReader *bytereader.ByteReader) string {
	domain := strings.Builder{}
	for {
		l, _ := responseReader.ReadSingleByte()
		domainPartLength := int(l)
		if domainPartLength == 0 {
			break
		}
		if domain.Len() != 0 {
			domain.WriteRune('.')
		}
		domainPart, _ := responseReader.ReadBytes(domainPartLength)
		domain.Write(domainPart)
	}
	return domain.String()
}

func parseAnswersFromResponse(response []byte) {
	domain := strings.Builder{}
	var domainPartStartIndex uint = 0
	var domainPartLength uint
	var recordTypeIndex uint
	for {
		domainPartLength = uint(response[domainPartStartIndex])
		if domainPartLength == 0 {
			recordTypeIndex = domainPartStartIndex + 1
			break
		}
		domain.Write(response[domainPartStartIndex+1 : domainPartStartIndex+domainPartLength+1])
		domain.WriteRune('.')
		domainPartStartIndex += domainPartLength + 1
	}
	fmt.Println("Domain: ", domain.String())
	fmt.Println("RecordType: ", MessageType(getUint16FromBytes(response[recordTypeIndex:recordTypeIndex+2])))
	fmt.Println("MessageClass: ", MessageClass(getUint16FromBytes(response[recordTypeIndex+2:recordTypeIndex+4])))
	offset := response[recordTypeIndex+4]
	if offset&192 == 192 {
		offset = offset&64 + response[recordTypeIndex+5]
		fmt.Println("Offset: ", offset)
	}
	fmt.Println("Response Type: ", getUint16FromBytes(response[recordTypeIndex+6:recordTypeIndex+8]))
	fmt.Println("Response Class: ", getUint16FromBytes(response[recordTypeIndex+8:recordTypeIndex+10]))
	fmt.Println("TTL: ", binary.BigEndian.Uint32(response[recordTypeIndex+10:recordTypeIndex+14]))
	fmt.Println("RDATALength: ", getUint16FromBytes(response[recordTypeIndex+14:recordTypeIndex+16]))
	fmt.Println("ResponseLength after rdata: ", len(response[recordTypeIndex+16:]))
	data := response[recordTypeIndex+16:]
	for i := 0; i < len(data); i++ {
		fmt.Print(uint(data[i]), " ")
	}
	fmt.Println()
}

func populateDnsHeaderWithMetadata(headerMeta uint16, dnsHeader *DnsHeader) error {
	dnsHeader.IsResponse = headerMeta&uint16(32768) == uint16(32768)
	dnsHeader.Opcode = OpCode(headerMeta >> 11 & uint16(15))
	dnsHeader.IsAuthoritativeAnswer = headerMeta&uint16(1024) == uint16(1024)
	dnsHeader.IsTruncatedMessage = headerMeta&uint16(512) == uint16(512)
	dnsHeader.IsRecursionDesired = headerMeta&uint16(256) == uint16(256)
	dnsHeader.IsRecursionSupportAvailable = headerMeta&uint16(128) == uint16(128)
	dnsHeader.ResponseCode = ResponseCode(headerMeta & uint16(15))
	return nil
}

//func convertByteArrayToInt32(array []byte) (int32, error) {
//	var convertedInt32 int32
//	err := binary.Read(bytes.NewReader(array), binary.BigEndian, &convertedInt32)
//	return convertedInt32, err
//}
//
//func getAnswers(response []byte) {
//
//}
