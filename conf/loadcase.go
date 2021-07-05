package conf

import (
	"encoding/csv"
	"os"
	"strconv"
	"strings"

	"github.com/zhaotao19860/dnstest/log"
)

//QueryINfo : the info about dns query
type QueryINfo struct {
	CaseName     string
	Domain       string
	Qtypes       []string
	Clientip     string
	ClientipMask uint8
	EDNSBufSize  uint16
}

//ExpectedInfo : the info used to match the answer
type ExpectedInfo struct {
	Rcode     string
	Answer    []string
	PartMatch bool
	AnswerNum int
}

//TestCase : 有了`json:network`这种注释，后面json解析就可以把相应的数据塞到对应的结构里面来
type TestCase struct {
	QueryINfo    QueryINfo
	ExpectedInfo ExpectedInfo
}

//Case : json file format
type Case struct {
	Case []TestCase
}

//LoadCSV : load the csv file
func LoadCSV(path string) *Case {
	var testcase Case
	var partMatch bool
	var addr string
	var mask uint8
	var temp uint64
	var ednsbufsize uint16
	var answernum int

	file, err := os.Open(path)
	if err != nil {
		log.Errorf("open file[%v] failed, err[%v]\n", path, err)
		return nil
	}

	fs, _ := file.Stat()
	if fs.Size() == 0 {
		log.Errorf("csv file[%v] is empty, skipping\n", path)
		return nil
	}

	// Read File into a Variable
	lines, err := csv.NewReader(file).ReadAll()
	if err != nil {
		log.Errorf("load file[%v] failed, err[%v]\n", path, err)
		return nil
	}

	// Loop through lines & turn into object
	for _, line := range lines {
		//初始化
		partMatch = false
		temp = 0
		ednsbufsize = 0
		answernum = -1
		addr = ""
		mask = 0
		//请求类型：支持多个类型，逗号分隔
		qtypes := strings.Split(line[2], ",")
		//edns client subnet：支持IP/掩码格式；支持掩码为空；支持字段为空
		subnet := line[3]
		if subnet != "" {
			i := strings.IndexByte(subnet, '/')
			if i < 0 {
				addr = subnet
				if strings.Contains(addr, ":") {
					mask = 128
				} else {
					mask = 32
				}
			} else {
				addr = subnet[:i]
				temp, err = strconv.ParseUint(subnet[i+1:], 10, 0)
				if err != nil {
					panic(err)
				}
				mask = uint8(temp)
			}
		}
		//dns answer and authority section
		answer := strings.Split(line[5], ",")
		//matchmethod: AllMatch/PartMatch/数字
		MatchMethod := line[6]
		if strings.Compare(MatchMethod, "AllMatch") == 0 {
			partMatch = false
		} else if strings.Compare(MatchMethod, "PartMatch") == 0 {
			partMatch = true
		} else {
			temp, err = strconv.ParseUint(MatchMethod, 10, 0)
			if err != nil {
				log.Errorf("load file[%v] failed, MatchMethod[%v] not support\n", path, MatchMethod)
				return nil
			}
			partMatch = true
			answernum = int(temp)
		}
		//ednsbufsize
		if len(line) >= 8 {
			if line[7] != "" {
				temp, err = strconv.ParseUint(line[7], 10, 0)
				if err != nil {
					panic(err)
				}
				ednsbufsize = uint16(temp)
			}
		}

		query := QueryINfo{CaseName: line[0], Domain: line[1], Qtypes: qtypes, Clientip: addr, ClientipMask: mask, EDNSBufSize: ednsbufsize}
		expect := ExpectedInfo{Rcode: line[4], Answer: answer, PartMatch: partMatch, AnswerNum: answernum}
		testcase.Case = append(testcase.Case, TestCase{QueryINfo: query, ExpectedInfo: expect})
		log.Debugf("[loadcsv] queryInfo: casename:[%v], domain:[%v], qtypes:[%v], clientip:[%v], ednsbufsize:[%v]\n",
			query.CaseName, query.Domain, query.Qtypes, query.Clientip, query.EDNSBufSize)
		log.Debugf("[loadcsv] expectedInfo: Rcode:[%v],  PartMatch:[%v], Answer:[%v], answernum:[%v]\n",
			expect.Rcode, expect.PartMatch, expect.Answer, expect.AnswerNum)
	}

	return &testcase
}
