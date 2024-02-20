package dnsresolvr

import (
	"dnsresolvr/internal/pkg/bytereader"
	"dnsresolvr/internal/pkg/utils"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

var rootNameServers = []string{
	"192.41.0.4",
	"170.247.170.2",
	"192.33.4.12",
	"199.7.91.13",
	"192.203.230.10",
	"192.5.5.241",
	"192.112.36.4",
	"198.97.190.53",
	"192.36.148.17",
	"192.58.128.30",
	"193.0.14.129",
	"199.7.83.42",
	"202.12.27.33",
}

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

	headerBytes = append(headerBytes, utils.ConvertUint16ToBytesArray(h.Id)...)
	headerBytes = append(headerBytes, h.getHeaderMetadata()...)
	headerBytes = append(headerBytes, utils.ConvertUint16ToBytesArray(h.QuestionCount)...)
	headerBytes = append(headerBytes, utils.ConvertUint16ToBytesArray(h.AnswerCount)...)
	headerBytes = append(headerBytes, utils.ConvertUint16ToBytesArray(h.NameServerRecordsCount)...)
	headerBytes = append(headerBytes, utils.ConvertUint16ToBytesArray(h.AdditionalRecordsCount)...)
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
	return utils.ConvertUint16ToBytesArray(headerMeta)
}

type DnsQueryQuestion struct {
	Qname  []byte
	Qtype  MessageType
	Qclass MessageClass
}

func (q DnsQueryQuestion) GetBytes() []byte {
	var questionBytes []byte
	questionBytes = append(questionBytes, q.Qname...)
	questionBytes = append(questionBytes, utils.ConvertUint16ToBytesArray(uint16(q.Qtype))...)
	questionBytes = append(questionBytes, utils.ConvertUint16ToBytesArray(uint16(q.Qclass))...)
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

type DnsAnswer struct {
	Domain      string
	Address     string
	RecordType  MessageType
	RecordClass MessageClass
	TTL         uint32
}

type DnsResponse struct {
	Header   *DnsHeader
	Question *DnsQueryQuestion
	Answers  []DnsAnswer
}

// Converts domain name string to qname format. e.g "www.google.com" gets converted to
// "3www6google3com0" in bytes
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
	queryHeader.Id = utils.GetRandomUint16()
	queryHeader.Opcode = StandardQuery
	queryHeader.QuestionCount = 1
	queryHeader.IsRecursionDesired = false
	queryQuestion := &DnsQueryQuestion{}
	queryQuestion.Qname = getDomainNameInQnameFormat(domainName)
	queryQuestion.Qclass = IN
	queryQuestion.Qtype = A
	query := &DnsQuery{}
	query.Header = *queryHeader
	query.Questions = []DnsQueryQuestion{*queryQuestion}
	return query
}

func queryDns(domainName string) ([]byte, error) {
	dnsQuery := generateDnsQuery(domainName)
	addr, err := net.ResolveUDPAddr("udp", "198.41.0.4:53")
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
	dnsResponse := &DnsResponse{}
	dnsHeader := &DnsHeader{}
	var dnsAnswers []DnsAnswer
	dnsResponse.Header = dnsHeader
	dnsResponse.Answers = dnsAnswers
	responseId, err := responseReader.ReadUint16()
	if err != nil {
		fmt.Println("Error parsing response ID: ", err)
	}
	dnsHeader.Id = responseId
	headerMeta, _ := responseReader.ReadUint16()
	_ = populateDnsHeaderWithMetadata(headerMeta, dnsHeader)
	dnsHeader.QuestionCount, _ = responseReader.ReadUint16()
	dnsHeader.AnswerCount, _ = responseReader.ReadUint16()
	fmt.Println("Answer count: ", dnsHeader.AnswerCount)
	dnsHeader.NameServerRecordsCount, _ = responseReader.ReadUint16()
	fmt.Println("Name Server Records: ", dnsHeader.NameServerRecordsCount)
	dnsHeader.AdditionalRecordsCount, _ = responseReader.ReadUint16()
	_ = readDomainFromResponse(responseReader)
	_, _ = responseReader.ReadUint16()
	_, _ = responseReader.ReadUint16()
	for i := 0; uint16(i) < dnsHeader.AnswerCount; i++ {
		ans := parseAnswersFromResponse(responseReader)
		dnsResponse.Answers = append(dnsResponse.Answers, *ans)
	}
	for j := 0; uint16(j) < dnsHeader.NameServerRecordsCount; j++ {
		parseAnswersFromResponse(responseReader)
	}
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

func readIpAddressFromResponse(addressInBytes []byte) string {
	address := strings.Builder{}
	for i := 0; i < 4; i++ {
		address.WriteString(strconv.Itoa(int(addressInBytes[i])))
		if i != 3 {
			address.WriteRune('.')
		}
	}
	return address.String()
}

func parseAnswersFromResponse(responseReader *bytereader.ByteReader) *DnsAnswer {
	o, _ := responseReader.ReadSingleByte()
	isDomainNameCompressedInAnswer := int(o)&192 == 192
	var originalReaderPosition int
	if isDomainNameCompressedInAnswer {
		o2, _ := responseReader.ReadSingleByte()
		offset := int(o)&63 + int(o2)
		originalReaderPosition = responseReader.GetCurrentPosition()
		_ = responseReader.SeekPosition(offset, io.SeekStart)
	}
	domainFromResponse := readDomainFromResponse(responseReader)
	if isDomainNameCompressedInAnswer {
		_ = responseReader.SeekPosition(originalReaderPosition, io.SeekStart)
	}
	rt, _ := responseReader.ReadUint16()
	rc, _ := responseReader.ReadUint16()
	ttl, _ := responseReader.ReadUint32()
	dataLength, _ := responseReader.ReadUint16()
	rdata, _ := responseReader.ReadBytes(int(dataLength))
	ipAddress := readIpAddressFromResponse(rdata)
	ans := &DnsAnswer{
		Domain:      domainFromResponse,
		RecordClass: MessageClass(rc),
		RecordType:  MessageType(rt),
		TTL:         ttl,
		Address:     ipAddress,
	}
	return ans
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
