package tracer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/iovisor/gobpf/bcc"
	bpf "github.com/iovisor/gobpf/bcc"
)

// #cgo CFLAGS: -I/usr/include/bcc/compat
// #cgo LDFLAGS: -lbcc
// #include <bcc/bcc_common.h>
// #include <bcc/libbpf.h>
// #include <netinet/in.h>
// #include <arpa/inet.h>
// #include "../catbpf_resources/bpfprogram.h"
import "C"

type Tracer struct {
	bpfModule               *bpf.Module
	perfMapSize             int
	perfMap                 *bpf.PerfMap
	lostChan                chan uint64
	eventChan               chan []byte
	doneEventChan           chan bool
	nConsumers              int
	consumerChan            chan Event
	doneConsumerChan        chan bool
	stopChan                chan bool
	totalHandledEvents      uint64
	totalIncompleteEvents   uint64
	totalLostEvents         uint64
	totalSavedEvents        uint64
	processEvents           uint64
	socketEvents            uint64
	diskEvents              uint64
	processIncompleteEvents uint64
	socketIncompleteEvents  uint64
	diskIncompleteEvents    uint64
	processLostEvents       uint32
	socketLostEvents        uint32
	diskLostEvents          uint32
	diskTruncatedEvents     uint64
	socketTruncatedEvents   uint64
	storage                 storage
	host                    string
	showStats               bool
	saveAsText              bool
	Exit                    bool
	totalCPUs               int
	tracedPid               uint32
}

type key struct {
	key uint32
}

/* Struct that stores the statistics per syscall */
type StatsInfo struct {
	N_entries uint32
	N_exits   uint32
	N_errors  uint32
	N_lost    uint32
}

type TracepointInfo struct {
	FunctionName       string
	TracepointFunction string
}

type KprobeInfo struct {
	FunctionName       string
	EntryProbeFunction string
	ExitProbeFunction  string
}

func InitTracer(bpfProgram string, childPID int, perfMapSize int, whitelist []string, stats bool, text bool) (*Tracer, error) {

	// Replace filters and load bpfprogram
	bpfProgram = strings.Replace(bpfProgram, "//PID_FILTER//", strconv.Itoa(childPID), -1)
	bpfProgram = strings.Replace(bpfProgram, "//WHITELIST_SIZE//", strconv.Itoa(len(whitelist)), -1)
	m := bpf.NewModule(bpfProgram, []string{})

	// Load and attach tracepoints

	var tracepoints = []TracepointInfo{
		{"syscalls:sys_enter_write", "entry__sys_write"},
		{"syscalls:sys_exit_write", "exit__sys_write"},
		{"syscalls:sys_enter_pwrite64", "enter_sys_pwrite64"},
		{"syscalls:sys_exit_pwrite64", "exit_sys_pwrite64"},
		{"syscalls:sys_enter_read", "entry__sys_read"},
		{"syscalls:sys_exit_read", "exit__sys_read"},
		{"syscalls:sys_enter_pread64", "enter_sys_pread64"},
		{"syscalls:sys_exit_pread64", "exit_sys_pread64"},
		{"sched:sched_process_fork", "on_fork"},
		{"sched:sched_process_exit", "on_exit"},
	}

	for _, elem := range tracepoints {
		tracepoint, err := m.LoadTracepoint(elem.TracepointFunction)
		if err != nil {
			log.Fatalf("Failed to load %s: %s\n", elem.TracepointFunction, err)
		}
		if err := m.AttachTracepoint(elem.FunctionName, tracepoint); err != nil {
			log.Fatalf("Failed to attach %s tracepoint: %s\n", elem.FunctionName, err)
		}
	}

	// Load and attach kprobes

	var probes = []KprobeInfo{
		{"tcp_connect", "entry__tcp_connect", "exit__connect"},
		{"ip4_datagram_connect", "entry__ip4_datagram_connect", "exit__connect"},
		{"inet_csk_accept", "", "exit__inet_csk_accept"},
		{"sock_sendmsg", "entry__sock_sendmsg", "exit__sock_sendmsg"},
		{"kernel_sendpage", "entry__sock_sendmsg", "exit__sock_sendmsg"},
		{"sock_recvmsg", "entry__sock_recvmsg", "exit__sock_recvmsg"},
		{"do_sys_open", "entry__do_sys_open", "exit__do_sys_open"},
		{"wake_up_new_task", "entry__wake_up_new_task", ""},
		{"do_wait", "", "exit__do_wait"},
	}

	for _, elem := range probes {

		if elem.EntryProbeFunction != "" {
			kprobe, err := m.LoadKprobe(elem.EntryProbeFunction)
			if err != nil {
				log.Fatalf("Failed to load %s: %s\n", elem.EntryProbeFunction, err)
			}
			// passing -1 for maxActive signifies to use the default
			// according to the kernel kretprobes documentation
			err = m.AttachKprobe(elem.FunctionName, kprobe, -1)
			if err != nil {
				log.Fatalf("Failed to attach %s Kprobe: %s\n", elem.FunctionName, err)
			}
		}
		if elem.ExitProbeFunction != "" {
			kretprobe, err := m.LoadKprobe(elem.ExitProbeFunction)
			if err != nil {
				log.Fatalf("Failed to load %s: %s\n", elem.ExitProbeFunction, err)
			}
			// passing -1 for maxActive signifies to use the default
			// according to the kernel kretprobes documentation
			err = m.AttachKretprobe(elem.FunctionName, kretprobe, -1)
			if err != nil {
				log.Fatalf("Failed to attach %s KretProbe: %s\n", elem.FunctionName, err)
			}
		}
	}

	// Setup file whitelist
	var index uint32 = 0
	whitelist_array := bpf.NewTable(m.TableId("whitelist_array"), m)
	for _, filename := range whitelist {
		filename_len := len(filename)
		if filename_len > 60 {
			log.Println("WARNING: whitelist filename length > 60 characters!!")
		}
		key := make([]byte, 4)
		bcc.GetHostByteOrder().PutUint32(key, index)
		cname := [C.WHITE_FILE_LEN]C.char{}
		for i := 0; i < filename_len && i < C.WHITE_FILE_LEN; i++ {
			cname[i] = C.char(filename[i])
		}
		whitefile := C.whitelist_entry_t{size: (C.int)(filename_len), name: cname}
		var leaf_bytes bytes.Buffer
		binary.Write(&leaf_bytes, bcc.GetHostByteOrder(), whitefile)
		if err := whitelist_array.Set(key, leaf_bytes.Bytes()); err != nil {
			return nil, fmt.Errorf("table.Set key 1 failed: %v", err)
		}
		index += 1
	}

	// Get Host CNAME
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("Failed to get hostname: %s", err)
	}
	host, err := net.LookupCNAME(hostname)
	if err != nil {
		return nil, fmt.Errorf("Failed to get host CNAME: %s", err)
	}

	tracer := &Tracer{
		bpfModule:               m,
		perfMapSize:             perfMapSize,
		perfMap:                 nil,
		eventChan:               nil,
		lostChan:                nil,
		nConsumers:              0,
		totalHandledEvents:      0,
		totalIncompleteEvents:   0,
		totalLostEvents:         0,
		totalSavedEvents:        0,
		processEvents:           0,
		socketEvents:            0,
		diskEvents:              0,
		processIncompleteEvents: 0,
		socketIncompleteEvents:  0,
		diskIncompleteEvents:    0,
		diskTruncatedEvents:     0,
		socketTruncatedEvents:   0,
		processLostEvents:       0,
		socketLostEvents:        0,
		diskLostEvents:          0,
		consumerChan:            make(chan Event, 10000),
		doneConsumerChan:        make(chan bool, 2),
		doneEventChan:           make(chan bool, 1),
		stopChan:                make(chan bool, 1),
		storage:                 jsonStor{},
		host:                    host,
		showStats:               stats,
		saveAsText:              text,
		Exit:                    false,
		totalCPUs:               runtime.NumCPU(),
		tracedPid:               uint32(childPID),
	}
	tracer.storage.Open()
	return tracer, nil
}

func (tracer *Tracer) Run() error {

	var err error
	// get bpf tables and open channels
	table := bpf.NewTable(tracer.bpfModule.TableId("events"), tracer.bpfModule)
	table_data := bpf.NewTable(tracer.bpfModule.TableId("percpu_array_dskwrite_data"), tracer.bpfModule)
	table_files := bpf.NewTable(tracer.bpfModule.TableId("percpu_array_file_info"), tracer.bpfModule)
	tracer.eventChan = make(chan []byte)
	tracer.lostChan = make(chan uint64)

	tracer.perfMap, err = bpf.InitPerfMapWithPageCnt(table, tracer.eventChan, tracer.lostChan, tracer.perfMapSize)
	if err != nil {
		log.Fatalf("Failed to init perf map: %s\n", err)
		return err
	}

	// Receive events
	go func() {
		setExit := false
		for {
			select {

			case dataRaw, ok := <-tracer.eventChan:
				if !ok {
					tracer.doneEventChan <- true
				}
				tracer.HandleEvent(&dataRaw, table_data, table_files)

			case lostCount, ok := <-tracer.lostChan:
				if ok {
					tracer.HandleLostEvent(lostCount)
				}
			default:
				if !setExit && tracer.Exit {
					tracer.stopChan <- true
					setExit = true
				}
			}
		}
	}()

	tracer.perfMap.Start()

	return nil
}

func (tracer *Tracer) RunConsumer() {
	tracer.nConsumers += 1
	for {
		select {
		case event, ok := <-tracer.consumerChan:
			if !ok {
				tracer.doneConsumerChan <- true
				return
			}
			if !tracer.saveAsText {
				event.ComputeMinhash()
			}
			tracer.storage.Save(event, event.GetType())
		}
	}
}

func (tracer *Tracer) Stop() {
	<-tracer.stopChan
	tracer.perfMap.Stop()
}

func (tracer *Tracer) Close() {
	tracer.bpfModule.Close()
	close(tracer.eventChan) // Close event channel
	close(tracer.lostChan)  // Close lost events channel
	<-tracer.doneEventChan
	close(tracer.consumerChan)               // Close consumer channel
	for i := 0; i < tracer.nConsumers; i++ { // Wait for all consumers to terminate
		<-tracer.doneConsumerChan
	}
	tracer.storage.Close() // Close storage

	if tracer.showStats { // Print stats
		log.Printf("TRACER STATS:")
		log.Printf("\t%-10s\t%10s\t%10s\t%10s\t%10s\n", "Event", "Handled", "Incomplete", "Truncated", "Lost")
		if tracer.processEvents > 0 {
			log.Printf("\t%-10s\t%10d\t%10d\t%10d\t%10d\n", "Process", tracer.processEvents, tracer.processIncompleteEvents, 0, tracer.processLostEvents)
		}
		if tracer.socketEvents > 0 {
			log.Printf("\t%-10s\t%10d\t%10d\t%10d\t%10d\n", "Socket", tracer.socketEvents, tracer.socketIncompleteEvents, tracer.socketTruncatedEvents, tracer.socketLostEvents)
		}
		if tracer.diskEvents > 0 {
			log.Printf("\t%-10s\t%10d\t%10d\t%10d\t%10d\n", "Disk", tracer.diskEvents, tracer.diskIncompleteEvents, tracer.diskTruncatedEvents, tracer.diskLostEvents)
		}
		log.Printf("\t%-10s\t%10d\t%10d\t%10d\t%10d\n", "TOTAL", tracer.totalHandledEvents, tracer.totalIncompleteEvents, tracer.socketTruncatedEvents+tracer.diskTruncatedEvents, tracer.processLostEvents+tracer.socketLostEvents+tracer.diskLostEvents)
		log.Printf("Saved events: %d\n", tracer.totalSavedEvents)
	}
}

func GetEventName(etype uint32) string {
	return C.GoString(C.event_str[etype])
}

func (tracer *Tracer) PrintStats() error {
	if !tracer.showStats {
		return nil
	}
	var totalCallEvents uint32 = 0
	var totalReturnedEvents uint32 = 0
	var totalErrorsEvents uint32 = 0
	var totalLostEvents uint32 = 0
	tableStats := bpf.NewTable(tracer.bpfModule.TableId("counts"), tracer.bpfModule)

	log.Printf("BPF Stats:\n")
	log.Printf("\t%-15s\t%5s\t%7s\t%6s\t%5s\n", "Event", "Calls", "Returns", "Errors", "Lost")
	iter := tableStats.Iter()
	for iter.Next() {
		key, leaf := iter.Key(), iter.Leaf()

		var k uint32
		var v StatsInfo
		if err := binary.Read(bytes.NewBuffer(key), bpf.GetHostByteOrder(), &k); err != nil {
			log.Printf("table.Iter failed: cannot decode key: %v", err)
		}
		if err := binary.Read(bytes.NewBuffer(leaf), bpf.GetHostByteOrder(), &v); err != nil {
			log.Printf("table.Iter failed: cannot decode value: %v", err)
		}

		log.Printf("\t%-10s\t%5d\t%5d\t%5d\t%5d\n", GetEventName(k), v.N_entries, v.N_exits, v.N_errors, v.N_lost)
		totalCallEvents += v.N_entries
		totalReturnedEvents += v.N_exits
		totalErrorsEvents += v.N_errors
		totalLostEvents += v.N_lost

		if C.is_disk_event(k) == 1 {
			tracer.diskLostEvents += v.N_lost
		} else if C.is_socket_event(k) == 1 {
			tracer.socketLostEvents += v.N_lost
		} else if C.is_process_event(k) == 1 {
			tracer.processLostEvents += v.N_lost
		}
	}
	log.Printf("\t%-10s\t%5d\t%5d\t%5d\t%5d\n", "TOTAL", totalCallEvents, totalReturnedEvents, totalErrorsEvents, totalLostEvents)

	if iter.Err() != nil {
		log.Printf("table.Iter failed: iteration finished with unexpected error: %v", iter.Err())
	}

	return nil
}

func (tracer *Tracer) HandleEvent(dataRaw *[]byte, table_data *bpf.Table, table_files *bpf.Table) {
	dataBuff := bytes.NewBuffer(*dataRaw)
	var err error

	context, err := ParseEventContext(dataBuff)
	if err != nil {
		return
	}
	context.Host = tracer.host
	context.Thread = fmt.Sprintf("%d@%s", context.Tgid, tracer.host)
	tracer.totalHandledEvents += 1

	var event Event
	switch context.Etype {
	case C.DSK_WRITE, C.DSK_READ:
		event = &EventDiskWriteRead{}
		tracer.diskEvents += 1

		index, n_ref, cpu, err := ParseEventRef(dataBuff)
		if err != nil {
			return
		}

		size, returned_value, err := ParseEventDataArgs(dataBuff)
		if err != nil {
			return
		}
		event.(*EventDiskWriteRead).Size = size
		event.(*EventDiskWriteRead).Returned_value = returned_value

		if returned_value > 4096 {
			tracer.diskTruncatedEvents += 1
		}

		data_incomplete := 0
		msg, msg_len, err := tracer.GetEventData(table_data, index, cpu, n_ref, returned_value)
		if err != nil {
			data_incomplete = 1
			tracer.totalIncompleteEvents += 1
			tracer.diskIncompleteEvents += 1
		}
		context.Msg = msg
		context.MsgLen = msg_len

		file, err := tracer.GetFileInfo(table_files, index, cpu, n_ref)
		if err != nil {
			if data_incomplete == 0 {
				tracer.totalIncompleteEvents += 1
				tracer.diskIncompleteEvents += 1
			}
		}
		event.(*EventDiskWriteRead).FileData = file

	case C.DSK_OPEN:
		event = &EventDisk{}
		tracer.diskEvents += 1
		index, n_ref, cpu, err := ParseEventRef(dataBuff)
		if err != nil {
			log.Printf("Failed to decode event ref: %v\n", err)
			return
		}

		file, err := tracer.GetFileInfo(table_files, index, cpu, n_ref)
		if err != nil {
			tracer.totalIncompleteEvents += 1
			tracer.diskIncompleteEvents += 1
		}
		event.(*EventDisk).FileData = file

	case C.SOCKET_CONNECT, C.SOCKET_ACCEPT:
		event = &EventSocket{}
		tracer.socketEvents += 1

		socket, err := ParseEventSocket(dataBuff, context.Etype)
		if err != nil || socket == nil {
			return
		}
		event.(*EventSocket).SetSocket(socket)

	case C.SOCKET_SEND, C.SOCKET_RECEIVE:
		event = &EventSocketSendRecv{}
		tracer.socketEvents += 1

		socket, err := ParseEventSocket(dataBuff, context.Etype)
		if err != nil || socket == nil {
			return
		}
		event.(*EventSocketSendRecv).SetSocket(socket)

		size, returned_value, err := ParseEventDataArgs(dataBuff)
		if err != nil {
			log.Printf("Failed to decode event args: %v\n", err)
			return
		}
		event.(*EventSocketSendRecv).Size = size
		event.(*EventSocketSendRecv).Returned_value = returned_value

		if returned_value > 4096 {
			tracer.socketTruncatedEvents += 1
		}

		index, n_ref, cpu, err := ParseEventRef(dataBuff)
		if err != nil {
			log.Printf("Failed to decode event ref: %v\n", err)
			return
		}

		msg, msg_len, err := tracer.GetEventData(table_data, index, cpu, n_ref, returned_value)
		if err != nil {
			tracer.totalIncompleteEvents += 1
			tracer.socketIncompleteEvents += 1
		}
		context.Msg = msg
		context.MsgLen = msg_len

	case C.PROCESS_CREATE, C.PROCESS_JOIN:
		event = &EventProcess{}
		tracer.processEvents += 1
		event.(*EventProcess).Child = bcc.GetHostByteOrder().Uint32(dataBuff.Next(4))
		return
	case C.PROCESS_END, C.PROCESS_START:
		event = &EventProcess{}
		tracer.processEvents += 1

		if context.Etype == C.PROCESS_END && context.Pid == tracer.tracedPid {
			tracer.Exit = true
		}
		return

	default:
		return
	}

	event.SetContext(context)
	tracer.consumerChan <- event
	tracer.totalSavedEvents += 1
}
func (tracer *Tracer) HandleLostEvent(lost uint64) {
	tracer.totalLostEvents += lost
}

func (tracer *Tracer) GetEventData(table_data *bpf.Table, index uint32, cpu uint16, ref uint32, size int32) (string, uint64, error) {
	// get table file descriptor
	fd := C.int(table_data.Config()["fd"].(int))

	// key corresponds to event index
	k := make([]byte, 4)
	bcc.GetHostByteOrder().PutUint32(k, index)
	keyP := unsafe.Pointer(&k[0])

	// prepare leaf
	leafSize := table_data.Config()["leaf_size"].(uint64)
	leaf := make([]byte, leafSize*uint64(tracer.totalCPUs))
	leafP := unsafe.Pointer(&leaf[0])

	// lookup elem
	r, err := C.bpf_lookup_elem(fd, keyP, leafP)
	if r != 0 {
		return "", 0, fmt.Errorf("Incomplete event: %v", err)
	}

	var contentBuff *bytes.Buffer
	if int(cpu) < 0 || int(cpu) > tracer.totalCPUs {
		log.Fatalf("Wrong cpu value. Got %v, expected < %v\n", cpu, tracer.totalCPUs)
	}
	start := uint64(cpu) * leafSize
	end := (uint64(cpu) + 1) * leafSize
	contentBuff = bytes.NewBuffer(leaf[start:end])

	// parse event data (content)

	if contentBuff.Len() < C.sizeof_message_content_t {
		return "", 0, fmt.Errorf("expected buf.Len() >= %d, but got %d", C.sizeof_message_content_t, contentBuff.Len())
	}

	msize := size
	if size > C.MAX_BUF_SIZE {
		msize = C.MAX_BUF_SIZE
	}

	msgBytes := contentBuff.Next(C.MAX_BUF_SIZE)
	msgCstr := (*C.char)(unsafe.Pointer(&msgBytes[0]))
	msg := C.GoStringN(msgCstr, C.int(msize))

	msg_len := bcc.GetHostByteOrder().Uint64(contentBuff.Next(8))
	m_ref := bcc.GetHostByteOrder().Uint32(contentBuff.Next(4))

	// check is ref is correct. Otherwise discard EventData and mark EventContext as incomplete
	if ref != m_ref {
		return "", 0, fmt.Errorf("Incomplete event: Failed to get data content")
	}

	return msg, msg_len, nil
}
func (tracer *Tracer) GetFileInfo(table_files *bpf.Table, index uint32, cpu uint16, ref uint32) (*FileData, error) {
	// get table file descriptor
	fd := C.int(table_files.Config()["fd"].(int))

	// key corresponds to event index
	k := make([]byte, 4)
	bcc.GetHostByteOrder().PutUint32(k, index)
	keyP := unsafe.Pointer(&k[0])

	// prepare leaf
	leafSize := table_files.Config()["leaf_size"].(uint64)
	leaf := make([]byte, leafSize*uint64(tracer.totalCPUs))
	leafP := unsafe.Pointer(&leaf[0])

	// lookup elem
	r, err := C.bpf_lookup_elem(fd, keyP, leafP)
	if r != 0 {
		return nil, fmt.Errorf("bpf_lookup_elem failed: %v", err)
	}
	// get the correct cpu item
	var contentBuff *bytes.Buffer
	if int(cpu) < 0 || int(cpu) > tracer.totalCPUs {
		log.Fatalf("Wrong cpu value. Got %v, expected < %v\n", cpu, tracer.totalCPUs)
	}
	start := uint64(cpu) * leafSize
	end := (uint64(cpu) + 1) * leafSize
	contentBuff = bytes.NewBuffer(leaf[start:end])

	// parse file info (content)

	if contentBuff.Len() < C.sizeof_file_info_t {
		return nil, fmt.Errorf("expected buf.Len() >= %d, but got %d", C.sizeof_file_info_t, contentBuff.Len())
	}

	file := &FileData{}

	file.filenameLen = bcc.GetHostByteOrder().Uint64(contentBuff.Next(8))
	file.FileDescriptor = bcc.GetHostByteOrder().Uint64(contentBuff.Next(8))
	offset := int64(bcc.GetHostByteOrder().Uint64(contentBuff.Next(8)))
	if offset != -1 {
		file.Offset = &offset
	}

	file.pipe_no = int32(bcc.GetHostByteOrder().Uint32(contentBuff.Next(4)))
	n_ref := bcc.GetHostByteOrder().Uint32(contentBuff.Next(4))

	filenameBytes := contentBuff.Next(C.FILENAME_MAX)
	filenameCstr := (*C.char)(unsafe.Pointer(&filenameBytes[0]))
	file.Filename = C.GoStringN(filenameCstr, C.int(file.filenameLen))

	// check is ref is correct. Otherwise discard EventData and mark EventContext as incomplete
	if ref != n_ref {
		return nil, fmt.Errorf("Incomplete event: Failed to get file data")
	}

	return file, nil
}

func ParseEventContext(buf *bytes.Buffer) (*EventContext, error) {
	if buf.Len() < C.sizeof_event_context_t {
		return nil, fmt.Errorf("expected buf.Len() >= %d, but got %d", C.sizeof_event_context_t, buf.Len())
	}

	context := &EventContext{}

	commBytes := buf.Next(16)
	commCstr := (*C.char)(unsafe.Pointer(&commBytes[0]))
	context.Comm = C.GoString(commCstr)

	context.Ktime = bcc.GetHostByteOrder().Uint64(buf.Next(8))

	context.Etype = bcc.GetHostByteOrder().Uint32(buf.Next(4))
	context.Pid = bcc.GetHostByteOrder().Uint32(buf.Next(4))
	context.Tgid = bcc.GetHostByteOrder().Uint32(buf.Next(4))

	return context, nil
}
func ParseEventRef(buf *bytes.Buffer) (uint32, uint32, uint16, error) {

	index := bcc.GetHostByteOrder().Uint32(buf.Next(4))
	n_ref := bcc.GetHostByteOrder().Uint32(buf.Next(4))
	cpu := bcc.GetHostByteOrder().Uint16(buf.Next(2))

	return index, n_ref, cpu, nil
}
func ParseEventDataArgs(buf *bytes.Buffer) (int32, int32, error) {

	size := int32(bcc.GetHostByteOrder().Uint32(buf.Next(4)))
	returned_value := int32(bcc.GetHostByteOrder().Uint32(buf.Next(4)))

	return size, returned_value, nil
}
func ParseEventSocket(buf *bytes.Buffer, etype uint32) (*SocketData, error) {

	socket := &SocketData{}

	saddr := make([]uint64, 2)
	saddr[0] = bcc.GetHostByteOrder().Uint64(buf.Next(8))
	saddr[1] = bcc.GetHostByteOrder().Uint64(buf.Next(8))

	daddr := make([]uint64, 2)
	daddr[0] = bcc.GetHostByteOrder().Uint64(buf.Next(8))
	daddr[1] = bcc.GetHostByteOrder().Uint64(buf.Next(8))

	src_port := bcc.GetHostByteOrder().Uint16(buf.Next(2))
	dst_port := bcc.GetHostByteOrder().Uint16(buf.Next(2))
	family := bcc.GetHostByteOrder().Uint16(buf.Next(2))

	socket_type := bcc.GetHostByteOrder().Uint16(buf.Next(2))

	if socket_type == syscall.SOCK_STREAM {
		socket.SocketType = "TCP"
	} else {
		socket.SocketType = "UDP"
	}

	sock_saddr := saddr
	sock_daddr := daddr
	var src_addr, dst_addr string

	if family == C.AF_INET {
		var src = make([]byte, C.INET_ADDRSTRLEN)
		var dst = make([]byte, C.INET_ADDRSTRLEN)
		sock_saddr[0] = saddr[1]
		sock_daddr[0] = daddr[1]
		C.inet_ntop(C.int(family), unsafe.Pointer(&sock_saddr[0]), (*C.char)(unsafe.Pointer(&src)), C.INET_ADDRSTRLEN)
		C.inet_ntop(C.int(family), unsafe.Pointer(&sock_daddr[0]), (*C.char)(unsafe.Pointer(&dst)), C.INET_ADDRSTRLEN)
		src_addr = net.ParseIP(C.GoString((*C.char)(unsafe.Pointer(&src)))).String()
		dst_addr = net.ParseIP(C.GoString((*C.char)(unsafe.Pointer(&dst)))).String()

	} else if family == C.AF_INET6 {

		// Handle IPv4-mapped IPv6 source socket addresses
		var src = make([]byte, C.INET6_ADDRSTRLEN)
		if saddr[0] == 0x0 && (saddr[1]&0xffff0000 == 0xffff0000) {
			sock_saddr[0] = saddr[1] >> 32
			C.inet_ntop(C.int(family), unsafe.Pointer(&sock_saddr[0]), (*C.char)(unsafe.Pointer(&src)), C.INET6_ADDRSTRLEN)
		} else {
			C.inet_ntop(C.int(family), unsafe.Pointer(&saddr), (*C.char)(unsafe.Pointer(&src)), C.INET6_ADDRSTRLEN)
		}
		src_addr = net.ParseIP(C.GoString((*C.char)(unsafe.Pointer(&src)))).String()

		// Handle IPv4-mapped IPv6 destination socket addresses
		var dst = make([]byte, C.INET6_ADDRSTRLEN)
		if daddr[0] == 0x0 && (daddr[1]&0xffff0000 == 0xffff0000) {
			// Convert IPv4-mapped destination IPv6 address to IPv4
			sock_daddr[0] = daddr[1] >> 32
			C.inet_ntop(C.int(family), unsafe.Pointer(&sock_daddr[0]), (*C.char)(unsafe.Pointer(&dst)), C.INET6_ADDRSTRLEN)

		} else {
			C.inet_ntop(C.int(family), unsafe.Pointer(&daddr), (*C.char)(unsafe.Pointer(&dst)), C.INET6_ADDRSTRLEN)
		}
		dst_addr = net.ParseIP(C.GoString((*C.char)(unsafe.Pointer(&dst)))).String()

	}

	if etype == C.SOCKET_ACCEPT || etype == C.SOCKET_RECEIVE {
		// The source and destination fields are swapped here, due to the kernel structures.
		socket.Src = dst_addr
		socket.SrcPort = dst_port
		socket.Dst = src_addr
		socket.DstPort = src_port
		socket.sock_saddr = sock_daddr
		socket.sock_daddr = sock_saddr
	} else {
		socket.Src = src_addr
		socket.SrcPort = src_port
		socket.Dst = dst_addr
		socket.DstPort = dst_port
		socket.sock_daddr = sock_daddr
		socket.sock_saddr = sock_saddr
	}
	socket.generate_socket_id()

	return socket, nil
}
