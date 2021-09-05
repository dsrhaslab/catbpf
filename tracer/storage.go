package tracer

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"sort"
)

var out_file *os.File
var stats map[uint32]int

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type storage interface {
	Open()
	Close()
	Save(v interface{}, etype uint32)
	PrintStats()
}

type jsonStor struct{}

func (j jsonStor) Open() {
	var err error
	out_file, err = os.Create("CATlog.json")
	check(err)
	stats = make(map[uint32]int)
}

func JSONMarshal(t interface{}) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(t)
	return buffer.Bytes(), err
}

func (j jsonStor) Save(v interface{}, etype uint32) {
	var m []byte
	m, _ = JSONMarshal(v)
	if len(m) > 0 {
		_, err := out_file.Write(m)
		check(err)
	}
}

func (j jsonStor) Close() {
	out_file.Close()
}

func (j jsonStor) PrintStats() {
	log.Printf("Saved events:\n")

	keys := make([]int, 0, len(stats))
	for k := range stats {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)

	for _, key := range keys {
		log.Printf("%8d %-18s %6d", key, GetEventName(uint32(key)), stats[uint32(key)])
	}
}
