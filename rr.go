package dnsr

import (
	"strings"
	"fmt"
	"github.com/miekg/dns"
)

// RR represents a DNS resource record.
type RR struct {
	Name  string
	Type  string
	Value string
	Class string
	Ttl   uint32
}

// RRs represents a slice of DNS resource records.
type RRs []RR

// emptyRRs is an empty, non-nil slice of RRs.
// It is used to save allocations at runtime.
var emptyRRs = RRs{}

// ICANN specifies that DNS servers should return the special value 127.0.53.53
// for A record queries of TLDs that have recently entered the root zone,
// that have a high likelyhood of colliding with private DNS names.
// The record returned is a notice to network administrators to adjust their
// DNS configuration.
// https://www.icann.org/resources/pages/name-collision-2013-12-06-en#127.0.53.53
const NameCollision = "127.0.53.53"

// String returns a string representation of an RR in zone-file format.
func (rr *RR) String() string {
	return rr.Name + "\t      " +fmt.Sprint(rr.Ttl)+"\t " + rr.Class + "\t" + rr.Type + "\t" + rr.Value
}

// convertRR converts a dns.RR to an RR.
// If the RR is not a type that this package uses,
// It will attempt to translate this if there are enough parameters
// Should all translation fail, it returns an undefined RR and false.
func convertRR(drr dns.RR) (RR, bool) {
	switch t := drr.(type) {
	case *dns.SOA:
		return RR{toLowerFQDN(t.Hdr.Name), "SOA", toLowerFQDN(t.Ns),dns.ClassToString[t.Hdr.Class],t.Hdr.Ttl}, true
	case *dns.NS:
		return RR{toLowerFQDN(t.Hdr.Name), "NS", toLowerFQDN(t.Ns),dns.ClassToString[t.Hdr.Class],t.Hdr.Ttl}, true
	case *dns.CNAME:
		return RR{toLowerFQDN(t.Hdr.Name), "CNAME", toLowerFQDN(t.Target),dns.ClassToString[t.Hdr.Class],t.Hdr.Ttl}, true
	case *dns.A:
		//fmt.Println("ttl = ",t.Hdr.Ttl, "class = ", dns.ClassToString[t.Hdr.Class])
		return RR{toLowerFQDN(t.Hdr.Name), "A", t.A.String(),dns.ClassToString[t.Hdr.Class],t.Hdr.Ttl}, true
	case *dns.AAAA:
		return RR{toLowerFQDN(t.Hdr.Name), "AAAA", t.AAAA.String(),dns.ClassToString[t.Hdr.Class],t.Hdr.Ttl}, true
	case *dns.TXT:
		return RR{toLowerFQDN(t.Hdr.Name), "TXT", strings.Join(t.Txt, "\t"),dns.ClassToString[t.Hdr.Class],t.Hdr.Ttl}, true
	default:
		fields := strings.Fields(drr.String())
		if len(fields) >= 4 {
			return RR{toLowerFQDN(fields[0]), fields[3], strings.Join(fields[4:], "\t"),"",0}, true
		}
	}
	return RR{}, false
}
