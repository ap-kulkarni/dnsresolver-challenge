package dnsresolvr

import (
	"encoding/hex"
	"slices"
	"strings"
	"testing"
)

func TestQnameBytesFromDomainName(t *testing.T) {
	got := getDomainNameInQnameFormat("dns.google.com")
	want, _ := hex.DecodeString("03646e7306676f6f676c6503636f6d00")
	if !slices.Equal(got, want) {
		t.Fatalf("Got: %s, Want: %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func TestQueryBytesInHex(t *testing.T) {
	query := generateDnsQuery("dns.google.com")
	got := hex.EncodeToString(query.GetBytes())
	want := "0000000100000000000003646e7306676f6f676c6503636f6d0000010001"
	if !strings.Contains(got, want) {
		t.Fatalf("Invalid query generated. Got: %s, Want: %s", got, want)
	}
}

func TestQueryDns(t *testing.T) {
	response, _ := queryDns("dns.google.com")
	parseResponse(response)
}
