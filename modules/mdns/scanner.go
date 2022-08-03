package mdns

// This mdns scanner constructs an easy-to-understand tree of services found
// over mdns. The logic is as follows:
// * Query '_services._dns-sd._udp.local' and read all the responses that match
//   the queries DNS-ID.
// * We linger on the socket for a while in order to parse potentially leaked
//   responses from multicast -> unicast forwarders.
// * For each returned record (can be multiple), send another request over the
//   same socket for the returned type.
// * For each response from the secondary queries, parse the values like so:
//    - IN PTR <NAME> == host-name
//    - IN TXT <NAME> == service-config
//    - IN SRV <NAME> n n <port> <local-name>
//    - <local-name> IN A <address>
// Result is something like:
/*
[
        {
          "service-name": "_workstation._tcp.local.",
          "servers": {
            "server-name": "4G-AC53U-7F8C.local.",
            "server-hosts": [
              {
                "host-protocol": 4,
                "host-address": "192.168.1.244",
                "host-port": 9
              }
            ]
          },
          "service-config": {
            "key": "val"
          }
        }
]
*/
import (
	"context"
	"encoding/binary"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/zmap/zgrab2"
)

const (
	_udpServiceQuery = "_services._dns-sd._udp.local."
)

type Module struct{}
type Result struct{}
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.UDPFlags
}

type Scanner struct {
	config *Flags
}

func (f *Flags) Help() string                       { return "" }
func (f *Flags) Validate(args []string) error       { return nil }
func (m *Module) Description() string               { return "Probe for mdns" }
func (m *Module) NewFlags() interface{}             { return new(Flags) }
func (m *Module) NewScanner() zgrab2.Scanner        { return new(Scanner) }
func (s *Scanner) GetName() string                  { return s.config.Name }
func (s *Scanner) GetTrigger() string               { return s.config.Trigger }
func (s *Scanner) InitPerSender(senderID int) error { return nil }
func (s *Scanner) Protocol() string                 { return "mdns" }
func (s *scan) Close() error                        { return s.conn.Close() }

type scan struct {
	conn     net.Conn
	target   *zgrab2.ScanTarget
	outgoing map[uint16]*dns.Msg
	incoming map[uint16]bool
	*sync.RWMutex
}

type Host struct {
	Proto uint8  `json:"host-protocol"`
	Addr  string `json:"host-address"`
	Port  uint16 `json:"host-port"`
}

type Server struct {
	Name  string  `json:"server-name"`
	Hosts []*Host `json:"server-hosts"`
}

type Service struct {
	Name   string            `json:"service-name"`
	Server *Server           `json:"servers,omitempty"`
	Config map[string]string `json:"service-config,omitempty"`
}

func (s *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	s.config = f
	return nil
}

func RegisterModule() {
	var module Module

	_, err := zgrab2.AddCommand("mdns", "mdns", module.Description(), 5353, &module)
	if err != nil {
		log.Fatal(err)
	}
}

func (s *Scanner) StartScan(target *zgrab2.ScanTarget) (*scan, error) {
	conn, err := target.OpenUDP(&s.config.BaseFlags, &s.config.UDPFlags)
	if err != nil {
		return nil, err
	}

	return &scan{
		conn:     conn,
		target:   target,
		outgoing: make(map[uint16]*dns.Msg),
	}, nil
}

func createQuery(t uint16, lname string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(lname, t)
	return m
}

func (s *scan) sendQuery(msg *dns.Msg) error {
	out, err := msg.Pack()
	if err != nil {
		return err
	}

	if _, err := s.conn.Write(out); err != nil {
		return err
	}

	s.outgoing[msg.Id] = msg

	return nil
}

// readReplies reads from the socket, parses dns messages, and attempts to find
// matching requests in the outbound queue.
func (s *scan) readReplies() error {
	buf := make([]byte, dns.MaxMsgSize)
	offset := 0
	gotResp := false

	for {
		s.conn.SetReadDeadline(time.Now().Add(time.Millisecond * 500))
		nread, err := s.conn.Read(buf[offset:])
		if err != nil {
			if err == context.DeadlineExceeded {
				// this is emitted by the zgrab2 side of things, informing us
				// that we have hit the configured --timeout for this
				// connection.
				return err
			}

			if err, ok := err.(net.Error); ok && err.Timeout() {
				if gotResp {
					break
				}
				continue
			}

			return err
		}

		if nread == 0 && gotResp {
			break
		}

		if binary.Size(buf) < dns.MinMsgSize {
			offset += nread
			continue
		}

		resp := new(dns.Msg)
		if err := resp.Unpack(buf); err != nil {
			return err
		}

		gotResp = true

		// find the matching query for this response
		if _, ok := s.outgoing[resp.Id]; !ok {
			continue
		}

		// append the responses to the proper dns sections of the original
		// question
		s.outgoing[resp.Id].Answer = append(
			s.outgoing[resp.Id].Answer, resp.Answer...)
		s.outgoing[resp.Id].Extra = append(
			s.outgoing[resp.Id].Extra, resp.Extra...)
	}

	return nil
}

// getRname returns a stringified version of the right-most dns label
func getRname(rr dns.RR) string {
	switch t := rr.(type) {
	case *dns.A:
		return t.A.String()
	case *dns.AAAA:
		return t.AAAA.String()
	case *dns.PTR:
		return t.Ptr
	case *dns.TXT:
		return strings.Join(t.Txt, ".")
	case *dns.SRV:
		return t.Target
	}
	return ""
}

func (s *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	scan, err := s.StartScan(&target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer scan.Close()

	msg := createQuery(dns.TypePTR, _udpServiceQuery)
	pid := msg.Id

	// send out the first service discovery query
	if err := scan.sendQuery(msg); err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	if err := scan.readReplies(); err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	// for each response (yes, multiple responses to the same query is quite
	// normal when multicast dns is running over unicast)
	for _, rec := range scan.outgoing {
		for _, answer := range rec.Answer {
			rname := getRname(answer)
			if rname == "" {
				continue
			}

			msg := createQuery(answer.Header().Rrtype, rname)
			if err := scan.sendQuery(msg); err != nil {
				return zgrab2.TryGetScanStatus(err), nil, err
			}
		}
	}

	// read all the replies that we just sent
	if err := scan.readReplies(); err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	services := make([]*Service, 0)

	// iterate over the responses and aggregate the responses into something
	// more human-readble.
	for id, resp := range scan.outgoing {
		if id == pid {
			continue
		}

		nmap := make(map[string]map[uint16][]dns.RR)

		for _, answer := range resp.Answer {
			key := answer.Header().Name
			typ := answer.Header().Rrtype

			if _, ok := nmap[key]; !ok {
				nmap[key] = make(map[uint16][]dns.RR)
			}

			if _, ok := nmap[key][typ]; !ok {
				nmap[key][typ] = make([]dns.RR, 0)
			}

			nmap[key][typ] = append(nmap[key][typ], answer)
		}

		for _, answer := range resp.Extra {
			key := answer.Header().Name
			typ := answer.Header().Rrtype

			if _, ok := nmap[key]; !ok {
				nmap[key] = make(map[uint16][]dns.RR)
			}

			if _, ok := nmap[key][typ]; !ok {
				nmap[key][typ] = make([]dns.RR, 0)
			}

			nmap[key][typ] = append(nmap[key][typ], answer)
		}

		serviceName := resp.Question[0].Name

		svc := &Service{
			Name:   serviceName,
			Config: make(map[string]string),
		}

		for _, hostRecord := range nmap[serviceName][dns.TypePTR] {
			servRecords := nmap[getRname(hostRecord)][dns.TypeSRV]
			servConfigs := nmap[getRname(hostRecord)][dns.TypeTXT]

			for _, servRecord := range servRecords {
				svr := &Server{
					Name:  getRname(servRecord),
					Hosts: make([]*Host, 0),
				}

				rec := servRecord.(*dns.SRV)
				port := rec.Port

				ipv4Recs := nmap[getRname(servRecord)][dns.TypeA]
				ipv6Recs := nmap[getRname(servRecord)][dns.TypeAAAA]

				for _, ipv4Rec := range ipv4Recs {
					svr.Hosts = append(svr.Hosts, &Host{
						Proto: 4,
						Addr:  getRname(ipv4Rec),
						Port:  port,
					})

				}

				for _, ipv6Rec := range ipv6Recs {
					svr.Hosts = append(svr.Hosts, &Host{
						Proto: 6,
						Addr:  getRname(ipv6Rec),
						Port:  port,
					})

				}

				svc.Server = svr
			}

			for _, servConfig := range servConfigs {
				rec := servConfig.(*dns.TXT)
				for _, ent := range rec.Txt {
					var (
						key string
						val string
					)

					kvs := strings.SplitN(ent, "=", 2)

					if len(kvs) == 2 {
						key = kvs[0]
						val = kvs[1]
					} else {
						key = kvs[0]
						val = ""
					}

					svc.Config[key] = val
				}
			}
		}

		services = append(services, svc)
	}

	return zgrab2.SCAN_SUCCESS, services, nil
}
