package dig

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	dnsTimeout time.Duration = 3 * time.Second
)

var roots = []string{"a.root-servers.net", "b.root-servers.net", "d.root-servers.net", "c.root-servers.net", "e.root-servers.net", "f.root-servers.net", "g.root-servers.net", "h.root-servers.net", "i.root-servers.net", "j.root-servers.net", "k.root-servers.net", "l.root-servers.net", "m.root-servers.net"}

// Dig parameter
type Dig struct {
	LocalAddr     string
	RemoteAddr    string
	EDNSSubnet    net.IP
	SourceNetmask uint8
	EDNSBufSize   uint16
	DialTimeout   time.Duration
	WriteTimeout  time.Duration
	ReadTimeout   time.Duration
	Protocol      string
	Retry         int
}

func (d *Dig) protocol() string {
	if d.Protocol != "" {
		return d.Protocol
	}
	return "udp"
}

func (d *Dig) dialTimeout() time.Duration {
	if d.DialTimeout != 0 {
		return d.DialTimeout
	}
	return dnsTimeout
}

func (d *Dig) readTimeout() time.Duration {
	if d.ReadTimeout != 0 {
		return d.ReadTimeout
	}
	return dnsTimeout
}

func (d *Dig) writeTimeout() time.Duration {
	if d.WriteTimeout != 0 {
		return d.WriteTimeout
	}
	return dnsTimeout
}

func (d *Dig) retry() int {
	if d.Retry > 0 {
		return d.Retry
	}
	return 1
}

func (d *Dig) remoteAddr() (string, error) {
	_, _, err := net.SplitHostPort(d.RemoteAddr)
	if err != nil {
		return d.RemoteAddr, errors.New("forget SetDNS ? " + err.Error())
	}
	return d.RemoteAddr, nil
}

func (d *Dig) conn() (net.Conn, error) {
	remoteaddr, err := d.remoteAddr()
	if err != nil {
		return nil, err
	}
	if d.LocalAddr == "" {
		return net.DialTimeout(d.protocol(), remoteaddr, d.dialTimeout())
	}
	return dial(d.protocol(), d.LocalAddr, remoteaddr, d.dialTimeout())
}

func dial(network string, local string, remote string, timeout time.Duration) (net.Conn, error) {
	network = strings.ToLower(network)
	dialer := new(net.Dialer)
	dialer.Timeout = timeout
	local = local + ":0" //端口0,系统会自动分配本机端口
	switch network {
	case "udp":
		addr, err := net.ResolveUDPAddr(network, local)
		if err != nil {
			return nil, err
		}
		dialer.LocalAddr = addr
	case "tcp":
		addr, err := net.ResolveTCPAddr(network, local)
		if err != nil {
			return nil, err
		}
		dialer.LocalAddr = addr
	}
	return dialer.Dial(network, remote)
}

// NewMsg generate send msg
func NewMsg(Type uint16, domain string) *dns.Msg {
	return newMsg(Type, domain)
}

func newMsg(Type uint16, domain string) *dns.Msg {
	domain = dns.Fqdn(domain)
	msg := new(dns.Msg)
	msg.Id = dns.Id()
	msg.RecursionDesired = true
	msg.Question = make([]dns.Question, 1)
	msg.Question[0] = dns.Question{
		Name:   domain,
		Qtype:  Type,
		Qclass: dns.ClassINET,
	}
	return msg
}

// Exchange send and read msg
func (d *Dig) Exchange(m *dns.Msg) (*dns.Msg, error) {
	var msg *dns.Msg
	var err error
	for i := 0; i < d.retry(); i++ {
		msg, err = d.exchange(m)
		if err == nil {
			return msg, err
		}
	}
	return msg, err
}

func (d *Dig) exchange(m *dns.Msg) (*dns.Msg, error) {
	var err error
	c := new(dns.Conn)
	c.Conn, err = d.conn()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	opt := m.IsEdns0()
	// If EDNS0 is used use that for size.
	if opt != nil && opt.UDPSize() >= dns.MinMsgSize {
		c.UDPSize = opt.UDPSize()
	}

	c.SetWriteDeadline(time.Now().Add(d.writeTimeout()))
	c.SetReadDeadline(time.Now().Add(d.readTimeout()))
	err = c.WriteMsg(m)
	if err != nil {
		return nil, err
	}
	res, err := c.ReadMsg()
	if err != nil {
		return nil, err
	}
	if res.Id != m.Id {
		return res, dns.ErrId
	}
	return res, nil
}

// SetTimeOut set timeout
func (d *Dig) SetTimeOut(t time.Duration) {
	d.ReadTimeout = t
	d.WriteTimeout = t
	d.DialTimeout = t
}

// SetDNS set host and port
func (d *Dig) SetDNS(host string) error {
	var ip string
	port := "53"
	switch strings.Count(host, ":") {
	case 0: //ipv4 or domain
		ip = host
	case 1: //ipv4 or domain
		var err error
		ip, port, err = net.SplitHostPort(host)
		if err != nil {
			return err
		}
	default: //ipv6
		if net.ParseIP(host).To16() != nil {
			ip = host
		} else {
			ip = host[:strings.LastIndex(host, ":")]
			port = host[strings.LastIndex(host, ":")+1:]
		}
	}
	ips, err := net.LookupIP(ip)
	if err != nil {
		return err
	}
	for _, addr := range ips {
		d.RemoteAddr = fmt.Sprintf("[%s]:%v", addr, port)
		return nil
	}
	return errors.New("no such host")
}

// SetEDNS0ClientSubnet set edns
func (d *Dig) SetEDNS0ClientSubnet(clientip string, mask uint8, ednsbufsize uint16) error {
	if len(clientip) > 0 {
		ip := net.ParseIP(clientip)
		if ip.To4() == nil {
			if ip.To16() == nil {
				return errors.New("not a valid ipv4 or ipv6")
			}
		}
		d.EDNSSubnet = ip
		d.SourceNetmask = mask
	}

	if ednsbufsize > 0 {
		d.EDNSBufSize = ednsbufsize
	} else {
		d.EDNSBufSize = 4096
	}

	return nil
}

// A send and get A
func (d *Dig) A(domain string) ([]*dns.A, error) {
	m := newMsg(dns.TypeA, domain)
	res, err := d.Exchange(m)
	if err != nil {
		return nil, err
	}
	var As []*dns.A
	for _, v := range res.Answer {
		if a, ok := v.(*dns.A); ok {
			As = append(As, a)
		}
	}
	return As, nil
}

// NS send and get NS
func (d *Dig) NS(domain string) ([]*dns.NS, error) {
	m := newMsg(dns.TypeNS, domain)
	res, err := d.Exchange(m)
	if err != nil {
		return nil, err
	}
	var Ns []*dns.NS
	for _, v := range res.Answer {
		if ns, ok := v.(*dns.NS); ok {
			Ns = append(Ns, ns)
		}
	}
	return Ns, nil
}

// CNAME send and get CNAME
func (d *Dig) CNAME(domain string) ([]*dns.CNAME, error) {
	m := newMsg(dns.TypeCNAME, domain)
	res, err := d.Exchange(m)
	if err != nil {
		return nil, err
	}
	var C []*dns.CNAME
	for _, v := range res.Answer {
		if c, ok := v.(*dns.CNAME); ok {
			C = append(C, c)
		}
	}
	return C, nil
}

// PTR send and get PTR
func (d *Dig) PTR(domain string) ([]*dns.PTR, error) {
	m := newMsg(dns.TypePTR, domain)
	res, err := d.Exchange(m)
	if err != nil {
		return nil, err
	}
	var P []*dns.PTR
	for _, v := range res.Answer {
		if p, ok := v.(*dns.PTR); ok {
			P = append(P, p)
		}
	}
	return P, nil
}

// TXT send and get TXT
func (d *Dig) TXT(domain string) ([]*dns.TXT, error) {
	m := newMsg(dns.TypeTXT, domain)
	res, err := d.Exchange(m)
	if err != nil {
		return nil, err
	}
	var T []*dns.TXT
	for _, v := range res.Answer {
		if t, ok := v.(*dns.TXT); ok {
			T = append(T, t)
		}
	}
	return T, nil
}

// AAAA send and get AAAA
func (d *Dig) AAAA(domain string) ([]*dns.AAAA, error) {
	m := newMsg(dns.TypeAAAA, domain)
	res, err := d.Exchange(m)
	if err != nil {
		return nil, err
	}
	var aaaa []*dns.AAAA
	for _, v := range res.Answer {
		if a, ok := v.(*dns.AAAA); ok {
			aaaa = append(aaaa, a)
		}
	}
	return aaaa, nil
}

// MX send and get MX
func (d *Dig) MX(domain string) ([]*dns.MX, error) {
	msg := newMsg(dns.TypeMX, domain)
	res, err := d.Exchange(msg)
	if err != nil {
		return nil, err
	}
	var M []*dns.MX
	for _, v := range res.Answer {
		if m, ok := v.(*dns.MX); ok {
			M = append(M, m)
		}
	}
	return M, nil
}

// SRV send and get SRV
func (d *Dig) SRV(domain string) ([]*dns.SRV, error) {
	msg := newMsg(dns.TypeSRV, domain)
	res, err := d.Exchange(msg)
	if err != nil {
		return nil, err
	}
	var S []*dns.SRV
	for _, v := range res.Answer {
		if s, ok := v.(*dns.SRV); ok {
			S = append(S, s)
		}
	}
	return S, nil
}

// CAA send and get CAA
func (d *Dig) CAA(domain string) ([]*dns.CAA, error) {
	msg := newMsg(dns.TypeCAA, domain)
	res, err := d.Exchange(msg)
	if err != nil {
		return nil, err
	}
	var C []*dns.CAA
	for _, v := range res.Answer {
		if c, ok := v.(*dns.CAA); ok {
			C = append(C, c)
		}
	}
	return C, nil
}

// ANY send and get ANY
func (d *Dig) ANY(domain string) ([]dns.RR, error) {
	m := newMsg(dns.TypeANY, domain)
	res, err := d.Exchange(m)
	if err != nil {
		return nil, err
	}
	return res.Answer, nil
}

// GetRR send and get ALL-RR
func (d *Dig) GetRR(Type uint16, domain string) ([]dns.RR, error) {
	m := newMsg(Type, domain)
	res, err := d.Exchange(m)
	if err != nil {
		return nil, err
	}
	return res.Answer, nil
}

// GetMsg send and get ALL-MSG
func (d *Dig) GetMsg(Type uint16, domain string) (*dns.Msg, error) {
	m := newMsg(Type, domain)
	d.setEDNS0(m)
	return d.Exchange(m)
}

func (d *Dig) setEDNS0(m *dns.Msg) {
	if d.EDNSSubnet == nil && d.EDNSBufSize == 0 {
		return
	}

	var o *dns.OPT
	if len(m.Extra) > 0 {
		o = m.Extra[0].(*dns.OPT)
	} else {
		o = new(dns.OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		o.SetUDPSize(d.EDNSBufSize)
		m.Extra = append(m.Extra, o)
	}

	if d.EDNSSubnet != nil {
		o.Option = append(o.Option, d.edns0clientsubnet(m))
	}
}

func (d *Dig) setECSOpt(m *dns.Msg) {
	var o *dns.OPT
	if len(m.Extra) > 0 {
		o = m.Extra[0].(*dns.OPT)
	} else {
		o = new(dns.OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		o.SetUDPSize(d.EDNSBufSize)
		m.Extra = append(m.Extra, o)
	}

	if d.EDNSSubnet != nil {
		o.Option = append(o.Option, d.edns0clientsubnet(m))
	}
}

func (d *Dig) edns0clientsubnet(m *dns.Msg) *dns.EDNS0_SUBNET {
	family := 1
	if d.EDNSSubnet.To4() == nil {
		family = 2
	}
	return &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        uint16(family),
		SourceNetmask: d.SourceNetmask,
		Address:       d.EDNSSubnet,
	}
}

//TraceResponse  dig +trace 响应
type TraceResponse struct {
	Server   string
	ServerIP string
	Msg      *dns.Msg
}

//Trace  类似于 dig +trace
func (d *Dig) Trace(domain string) ([]TraceResponse, error) {
	var responses = make([]TraceResponse, 0)
	var servers = make([]string, 0, 13)
	var server = randserver(roots)
	for {
		if err := d.SetDNS(server); err != nil {
			return responses, err
		}
		msg, err := d.GetMsg(dns.TypeA, domain)
		if err != nil {
			return responses, fmt.Errorf("%s:%v", server, err)
		}
		var rsp TraceResponse
		rsp.Server = server
		rsp.ServerIP = d.RemoteAddr
		rsp.Msg = msg
		responses = append(responses, rsp)
		switch msg.Authoritative {
		case false:
			servers = servers[:0]
			for _, v := range msg.Ns {
				ns := v.(*dns.NS)
				servers = append(servers, ns.Ns)
			}
			if len(servers) == 0 {
				return responses, nil
			}
			server = randserver(servers)
		case true:
			return responses, nil
		}
	}
}

func randserver(servers []string) string {
	length := len(servers)
	switch length {
	case 0:
		return ""
	case 1:
		return servers[0]
	}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return servers[r.Intn(length)]
}

//IsPolluted  返回domain是否被污染
func IsPolluted(domain string) (bool, error) {
	var dig Dig
	rsps, err := dig.Trace(domain)
	if err != nil {
		return false, err
	}
	length := len(rsps)
	if length < 1 {
		//should not have happened
		return false, fmt.Errorf("empty message")
	}
	last := rsps[length-1]
	if !last.Msg.Authoritative {
		return true, nil
	}
	return false, nil
}

func (d *Dig) setMsg(m *dns.Msg, opts []string) {
	var opt, optVal string
	for _, item := range opts {
		eq := strings.Index(item, "=")
		if eq < 0 {
			opt = item
			optVal = ""
		} else {
			opt = item[0:eq]
			optVal = item[eq+1:]
		}
		d.setMsgOpt(m, opt, optVal)
	}
}

func (d *Dig) setMsgOpt(m *dns.Msg, opt, optVal string) {
	switch opt {
	case "subnet":
		d.EDNSSubnet = net.ParseIP(optVal)
		d.setECSOpt(m)

	//其他dig opt待支持
	default:
		break
	}
}
