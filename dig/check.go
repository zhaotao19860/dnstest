package dig

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/zhaotao19860/dnstest/conf"
	"github.com/zhaotao19860/dnstest/log"
)

// SucceededNum testcase success num
var SucceededNum int

// FailedNum testcase failed num
var FailedNum int

//ResultInfo : the info used to match the Answer
type ResultInfo struct {
	CaseName    string //test case name
	MatchStatus bool   //true: success; false: failed
	Msg         string //error message
}

func genResult(rInfo *ResultInfo, equalNum int, returnAnswerLen int, caseAnswerLen int, PartMatch bool, expectAnswerLen int, casename string) {
	if expectAnswerLen >= 0 {
		if equalNum == expectAnswerLen {
			rInfo.MatchStatus = true
			rInfo.Msg = "match perfect"
		} else {
			log.Errorf("[%v] match failed: equalNum[%v] returnAnswerLen[%v] caseAnswerLen[%v]  PartMatch[%v] expectAnswerLen[%v].\n",
				casename, equalNum, returnAnswerLen, caseAnswerLen, PartMatch, expectAnswerLen)
			rInfo.Msg = "match failed"
		}
	} else {
		if equalNum == caseAnswerLen && equalNum == returnAnswerLen {
			rInfo.MatchStatus = true
			rInfo.Msg = "match perfect"
		} else if 1 <= equalNum && equalNum <= caseAnswerLen && equalNum == returnAnswerLen && PartMatch {
			rInfo.MatchStatus = true
			rInfo.Msg = "match part"
		} else {
			rInfo.MatchStatus = false
			log.Errorf("[%v] match failed: equalNum[%v] returnAnswerLen[%v] caseAnswerLen[%v]  PartMatch[%v] expectAnswerLen[%v].\n",
				casename, equalNum, returnAnswerLen, caseAnswerLen, PartMatch, expectAnswerLen)
			rInfo.Msg = "match failed"
		}
	}

	rInfo.CaseName = casename
	log.Debugf("[%v] Result: equalNum:[%v] returnAnswerLen[%v] caseAnswerLen[%v] expectAnswerLen[%v].\n",
		casename, equalNum, returnAnswerLen, caseAnswerLen, expectAnswerLen)
}

func getRR(expectedInfo conf.ExpectedInfo, rrs *[]dns.RR) error {
	for i := range expectedInfo.Answer {
		if expectedInfo.Answer[i] != "" {
			rr, err := dns.NewRR(expectedInfo.Answer[i])
			if err != nil {
				log.Errorf("dns.NewRR error: expectedInfo.Answer[%v].\n", expectedInfo.Answer[i])
				return err
			}
			*rrs = append(*rrs, rr)
		}
	}
	return nil
}

//cmpA : compare the expected with the response
func cmpA(answer dns.RR, Arr []dns.A, equalNum *int) {
	for i := range Arr {
		if strings.Compare(Arr[i].A.String(), answer.(*dns.A).A.String()) == 0 {
			*equalNum++
			break
		}
	}
}

//cmpAAAA : compare the expected with the response
func cmpAAAA(answer dns.RR, AAAArr []dns.AAAA, equalNum *int) {
	for i := range AAAArr {
		if strings.Compare(AAAArr[i].AAAA.String(), answer.(*dns.AAAA).AAAA.String()) == 0 {
			*equalNum++
			break
		}
	}
}

//cmpSOA : compare the expected with the response
func cmpSOA(answer dns.RR, SOArr []dns.SOA, equalNum *int) {
	for i := range SOArr {
		if SOArr[i].Ns == answer.(*dns.SOA).Ns &&
			SOArr[i].Mbox == answer.(*dns.SOA).Mbox &&
			//SOArr[i].Serial == answer.(*dns.SOA).Serial &&
			SOArr[i].Refresh == answer.(*dns.SOA).Refresh &&
			SOArr[i].Retry == answer.(*dns.SOA).Retry &&
			SOArr[i].Expire == answer.(*dns.SOA).Expire &&
			SOArr[i].Minttl == answer.(*dns.SOA).Minttl {
			*equalNum++
			break
		}
	}
}

//cmpNS : compare the expected with the response
func cmpNS(answer dns.RR, NSrr []dns.NS, equalNum *int) {
	for i := range NSrr {
		if NSrr[i].Ns == answer.(*dns.NS).Ns {
			*equalNum++
			break
		}
	}
}

//cmpCNAME : compare the expected with the response
func cmpCNAME(answer dns.RR, CNAMErr []dns.CNAME, equalNum *int) {
	for i := range CNAMErr {
		if CNAMErr[i].Target == answer.(*dns.CNAME).Target {
			*equalNum++
			break
		}
	}
}

//cmpPTR : compare the expected with the response
func cmpPTR(answer dns.RR, PTRrr []dns.PTR, equalNum *int) {
	for i := range PTRrr {
		if PTRrr[i].Ptr == answer.(*dns.PTR).Ptr {
			*equalNum++
			break
		}
	}
}

//cmpTXT : compare the expected with the response
func cmpTXT(answer dns.RR, TXTrr []dns.TXT, equalNum *int) {
	for i := range TXTrr {
		count := 0
		for j, v := range answer.(*dns.TXT).Txt {
			if v == TXTrr[i].Txt[j] {
				count++
			}
		}
		if count == len(answer.(*dns.TXT).Txt) {
			*equalNum++
			break
		}
	}
}

//cmpMX : compare the expected with the response
func cmpMX(answer dns.RR, MXrr []dns.MX, equalNum *int) {
	for i := range MXrr {
		if MXrr[i].Preference == answer.(*dns.MX).Preference &&
			MXrr[i].Mx == answer.(*dns.MX).Mx {
			*equalNum++
			break
		}
	}
}

//cmpSRV : compare the expected with the response
func cmpSRV(answer dns.RR, SRVrr []dns.SRV, equalNum *int) {
	for i := range SRVrr {
		if SRVrr[i].Priority == answer.(*dns.SRV).Priority &&
			SRVrr[i].Weight == answer.(*dns.SRV).Weight &&
			SRVrr[i].Port == answer.(*dns.SRV).Port &&
			SRVrr[i].Target == answer.(*dns.SRV).Target {
			*equalNum++
			break
		}
	}
}

//cmpCAA : compare the expected with the response
func cmpCAA(answer dns.RR, CAArr []dns.CAA, equalNum *int) {
	for i := range CAArr {
		if CAArr[i].Flag == answer.(*dns.CAA).Flag &&
			CAArr[i].Tag == answer.(*dns.CAA).Tag &&
			CAArr[i].Value == answer.(*dns.CAA).Value {
			*equalNum++
			break
		}
	}
}

//checkA : get A rr datas from answer
func checkA(answer dns.RR, expect []dns.RR, equalNum *int) {
	var Arr []dns.A
	for _, v := range expect {
		if a, ok := v.(*dns.A); ok {
			Arr = append(Arr, *a)
		}
	}
	cmpA(answer, Arr, equalNum)
}

//checkAAAA : get AAAA rr datas from answer
func checkAAAA(answer dns.RR, expect []dns.RR, equalNum *int) {
	var AAAArr []dns.AAAA
	for _, v := range expect {
		if a, ok := v.(*dns.AAAA); ok {
			AAAArr = append(AAAArr, *a)
		}
	}
	cmpAAAA(answer, AAAArr, equalNum)
}

//checkSOA : get SOA rr datas from answer
func checkSOA(answer dns.RR, expect []dns.RR, equalNum *int) {
	var SOArr []dns.SOA
	for _, v := range expect {
		if a, ok := v.(*dns.SOA); ok {
			SOArr = append(SOArr, *a)
		}
	}
	cmpSOA(answer, SOArr, equalNum)
}

//checkNS : get NS rr datas from answer
func checkNS(answer dns.RR, expect []dns.RR, equalNum *int) {
	var NSrr []dns.NS
	for _, v := range expect {
		if a, ok := v.(*dns.NS); ok {
			NSrr = append(NSrr, *a)
		}
	}
	cmpNS(answer, NSrr, equalNum)
}

//checkCNAME : get CNAME rr datas from answer
func checkCNAME(answer dns.RR, expect []dns.RR, equalNum *int) {
	var CNAMErr []dns.CNAME
	for _, v := range expect {
		if a, ok := v.(*dns.CNAME); ok {
			CNAMErr = append(CNAMErr, *a)
		}
	}
	cmpCNAME(answer, CNAMErr, equalNum)
}

//checkPTR : get PTR rr datas from answer
func checkPTR(answer dns.RR, expect []dns.RR, equalNum *int) {
	var PTRrr []dns.PTR
	for _, v := range expect {
		if a, ok := v.(*dns.PTR); ok {
			PTRrr = append(PTRrr, *a)
		}
	}
	cmpPTR(answer, PTRrr, equalNum)
}

//checkTXT : get TXT rr datas from answer
func checkTXT(answer dns.RR, expect []dns.RR, equalNum *int) {
	var TXTrr []dns.TXT
	for _, v := range expect {
		if a, ok := v.(*dns.TXT); ok {
			TXTrr = append(TXTrr, *a)
		}
	}
	cmpTXT(answer, TXTrr, equalNum)
}

//checkMX : get MX rr datas from answer
func checkMX(answer dns.RR, expect []dns.RR, equalNum *int) {
	var MXrr []dns.MX
	for _, v := range expect {
		if a, ok := v.(*dns.MX); ok {
			MXrr = append(MXrr, *a)
		}
	}
	cmpMX(answer, MXrr, equalNum)
}

//checkSRV : get SRV rr datas from answer
func checkSRV(answer dns.RR, expect []dns.RR, equalNum *int) {
	var SRVrr []dns.SRV
	for _, v := range expect {
		if a, ok := v.(*dns.SRV); ok {
			SRVrr = append(SRVrr, *a)
		}
	}
	cmpSRV(answer, SRVrr, equalNum)
}

//checkCAA : get CAA rr datas from answer
func checkCAA(answer dns.RR, expect []dns.RR, equalNum *int) {
	var CAArr []dns.CAA
	for _, v := range expect {
		if a, ok := v.(*dns.CAA); ok {
			CAArr = append(CAArr, *a)
		}
	}
	cmpCAA(answer, CAArr, equalNum)
}

func logMsg(testcase conf.TestCase, rinfo ResultInfo, server string) {
	log.Debugf("[%v] queryInfo: domain:[%v], qtypes:%v, server:[%v], clientip:[%v]\n",
		rinfo.CaseName, testcase.QueryINfo.Domain, testcase.QueryINfo.Qtypes, server, testcase.QueryINfo.Clientip)
	log.Debugf("[%v] expectedInfo: Rcode:[%v],  PartMatch:[%v], Answer:%v\n",
		rinfo.CaseName, testcase.ExpectedInfo.Rcode, testcase.ExpectedInfo.PartMatch, testcase.ExpectedInfo.Answer)
	log.Infof("[%v] resultInfo: result:[%v] msg:[%v]\n",
		rinfo.CaseName, rinfo.MatchStatus, rinfo.Msg)
}

//DNSCheck dig+compare
//support qtype:
//              A;AAAA;CNAME;NS;MX;PTR;CAA;SRV;TXT;SOA
//support rcode:
//              NOERROR;FORMERR;SERVFAIL;NXDOMAIN;NOTIMPL;
//				REFUSED;YXDOMAIN;YXRRSET;NXRRSET;NOTAUTH;NOTZONE;BADSIG;
//				BADKEY;BADTIME;BADMODE;BADNAME;BADALG;BADTRUNC;BADCOOKIE
func DNSCheck(goroutineWaitGroup *sync.WaitGroup, testcase conf.TestCase, server string) {

	var dig Dig
	var qtypes []uint16
	var rcode int
	var expect []dns.RR
	var rinfo ResultInfo
	var mutexSuc sync.Mutex
	var mutexFail sync.Mutex
	var err error

	defer goroutineWaitGroup.Done()
	queryInfo := testcase.QueryINfo
	expectedInfo := testcase.ExpectedInfo
	casename := queryInfo.CaseName
	rcodeUpper := strings.ToUpper(expectedInfo.Rcode)

	for _, v := range queryInfo.Qtypes {
		qtypeUpper := strings.ToUpper(v)
		if t, ok := dns.StringToType[qtypeUpper]; ok {
			qtypes = append(qtypes, t)
		} else {
			log.Errorf("[%v] qtype:[%v] not support.\n", casename, queryInfo.Qtypes)
			rinfo = ResultInfo{CaseName: casename, MatchStatus: false, Msg: "qtype not support"}
			goto all_end
		}
	}

	if t, ok := dns.StringToRcode[rcodeUpper]; ok {
		rcode = t
	} else {
		log.Errorf("[%v] rcode:[%v] not support.\n", casename, expectedInfo.Rcode)
		rinfo = ResultInfo{CaseName: casename, MatchStatus: false, Msg: "rcode not support"}
		goto all_end
	}

	//set nameServer ip
	err = dig.SetDNS(server)
	if err != nil {
		log.Errorf("[%v] server:[%v] err:[%v].\n", casename, server, err.Error())
		rinfo = ResultInfo{CaseName: casename, MatchStatus: false, Msg: "server ip error"}
		goto all_end
	}

	//set Clientip for edns0 subnet
	if len(queryInfo.Clientip) > 0 || queryInfo.EDNSBufSize > 0 {
		err = dig.SetEDNS0ClientSubnet(queryInfo.Clientip, queryInfo.ClientipMask, queryInfo.EDNSBufSize)
		if err != nil {
			log.Errorf("[%v] queryInfo.Clientip:[%v] err:[%v].\n", casename, queryInfo.Clientip, err.Error())
			rinfo = ResultInfo{CaseName: casename, MatchStatus: false, Msg: "client ip error"}
			goto all_end
		}
	}

	//get the expect rr
	err = getRR(expectedInfo, &expect)
	if err != nil {
		rinfo = ResultInfo{CaseName: casename, MatchStatus: false, Msg: err.Error()}
		goto all_end
	}

	//dig
	for i, qtype := range qtypes {
		res, err := dig.GetMsg(qtype, queryInfo.Domain)
		if err != nil {
			log.Errorf("[%v] dig.GetMsg failed:qtype[%v] queryInfo.Domain[%v] err:[%v].\n", casename, qtype, queryInfo.Domain, err.Error())
			rinfo = ResultInfo{MatchStatus: false, Msg: err.Error()}
			goto all_end
		}
		log.Debugf(casename +
			"\nResponseInfo: \n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n" +
			res.String() +
			">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n")

		//match Rcode
		if rcode != res.Rcode {
			log.Errorf("[%v] Rcode not match: rcode[%v] res.Rcode[%v].\n", casename, rcode, res.Rcode)
			rinfo = ResultInfo{CaseName: casename, MatchStatus: false, Msg: "Rcode not match"}
			goto all_end
		}

		//get the answer and authority rr
		answer := append(res.Answer,res.Ns...)

		//check if len is 0
		if len(answer) == 0 || len(expect) == 0 {
			genResult(&rinfo, 0, len(answer), len(expect), expectedInfo.PartMatch, expectedInfo.AnswerNum, casename)
			if !rinfo.MatchStatus || i == len(qtypes)-1 {
				goto all_end
			}
			continue
		}

		//check the answer and authority rr
		equalNum := 0
		for _, v := range answer {
			rrtype := v.Header().Rrtype
			switch rrtype {
			case dns.TypeA:
				checkA(v, expect, &equalNum)
			case dns.TypeAAAA:
				checkAAAA(v, expect, &equalNum)
			case dns.TypeSOA:
				checkSOA(v, expect, &equalNum)
			case dns.TypeNS:
				checkNS(v, expect, &equalNum)
			case dns.TypeCNAME:
				checkCNAME(v, expect, &equalNum)
			case dns.TypePTR:
				checkPTR(v, expect, &equalNum)
			case dns.TypeTXT:
				checkTXT(v, expect, &equalNum)
			case dns.TypeMX:
				checkMX(v, expect, &equalNum)
			case dns.TypeSRV:
				checkSRV(v, expect, &equalNum)
			case dns.TypeCAA:
				checkCAA(v, expect, &equalNum)
			default:
				log.Errorf("[%v] unsupport rrtype[%v]\n", casename, dns.TypeToString[rrtype])
			}
		}
		genResult(&rinfo, equalNum, len(answer), len(expect), expectedInfo.PartMatch, expectedInfo.AnswerNum, casename)
		if !rinfo.MatchStatus {
			goto all_end
		}
	}
all_end:
	if !rinfo.MatchStatus {
		mutexFail.Lock()
		FailedNum++
		mutexFail.Unlock()
	} else {
		mutexSuc.Lock()
		SucceededNum++
		mutexSuc.Unlock()
	}
	logMsg(testcase, rinfo, server)
}

type DigArgs struct {
	NameServer string
	Port       uint16
	Domain     string
	DType      uint16
	Opts       []string
}

func parseDigArgs(args []string) (*DigArgs, error) {
	var nsCnt, domainCnt, typeCnt int
	var ns, domain, dtype string
	var iType uint16
	opts := make([]string, 0, 5)
	for _, arg := range args {
		if arg[0] == '@' {
			nsCnt++
			ns = arg[1:]
		} else if arg[0] == '+' {
			opts = append(opts, arg[1:])
		} else if strings.Contains(arg, ".") {
			domainCnt++
			domain = arg
		} else {
			typeCnt++
			dtype = arg
		}
	}

	if nsCnt != 1 {
		return nil, fmt.Errorf("NS个数必须设置1个")
	}

	if domainCnt > 1 {
		return nil, fmt.Errorf("一次只能dig一个domain")
	}
	if _, valid := dns.IsDomainName(domain); !valid {
		return nil, fmt.Errorf("domain格式不合法")
	}

	if typeCnt > 1 {
		return nil, fmt.Errorf("一次只能dig一个类型")
	}
	if typeCnt == 0 {
		iType = 1
	} else {
		_, ok := dns.StringToType[strings.ToUpper(dtype)]
		if !ok {
			return nil, fmt.Errorf("类型[%s]不合法", dtype)
		}
		iType = dns.StringToType[strings.ToUpper(dtype)]
	}

	addrs, err := net.LookupHost(ns)
	if err != nil {
		return nil, fmt.Errorf("NS不能解析，请确认")
	}

	return &DigArgs{
		NameServer: addrs[0], //只使用第一个解出来的NS A记录
		Domain:     domain,
		DType:      iType,
		Opts:       opts,
	}, nil
}

func digOnce(arg *DigArgs) {
	m := newMsg(arg.DType, arg.Domain)

	d := Dig{
		RemoteAddr:   fmt.Sprintf("[%s]:%d", arg.NameServer, arg.Port),
		DialTimeout:  dnsTimeout,
		WriteTimeout: dnsTimeout,
		ReadTimeout:  dnsTimeout,
		EDNSBufSize:  4096,
		SourceNetmask: 32,
		Protocol:     "udp",
		Retry:        1,
	}

	d.setMsg(m, arg.Opts)
	fmt.Printf("请求msg:\n%s", m.String())
	rsp, err := d.Exchange(m)
	if err != nil {
		fmt.Printf("返回msg失败:%s", err.Error())
	}
	fmt.Printf("\n返回msg:\n%s", rsp.String())
}

func DigOneShot(port uint16, args []string) {
	digArgs, err := parseDigArgs(args)
	if err != nil {
		fmt.Printf("invalid args: %s\n", err.Error())
		return
	}

	digArgs.Port = port

	digOnce(digArgs)
}
