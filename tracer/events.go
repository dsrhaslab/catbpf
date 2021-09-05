package tracer

import (
	"fmt"

	minhashlsh "github.com/ekzhu/minhash-lsh"
)

type Event interface {
	GetType() uint32
	SetContext(*EventContext)
	ComputeMinhash()
}

type ExtraData struct {
	Host      string   `json:"host,omitempty"`
	Comm      string   `json:"comm,omitempty"`
	Msg       string   `json:"msg,omitempty"`
	MsgLen    uint64   `json:"msg_len,omitempty"`
	Signature []uint64 `json:"signature,omitempty"`
}

/* BaseEvent contains the context of the event as well as the index for obtaining the corresponding content */
type EventContext struct {
	Ktime     uint64 `json:"timestamp"`
	Etype     uint32 `json:"type"`
	Thread    string `json:"thread"`
	Pid       uint32 `json:"-"`
	Tgid      uint32 `json:"pid,omitempty"`
	ExtraData `json:"data,omitempty"`
}

type FileData struct {
	Filename       string `json:"filename,omitempty"`
	filenameLen    uint64 `json:"-"`
	FileDescriptor uint64 `json:"fd"`
	Offset         *int64 `json:"offset,omitempty"`
	pipe_no        int32  `json:"-"`
}

type EventDisk struct {
	EventContext
	*FileData `json:",omitempty"`
}

type EventDiskWriteRead struct {
	EventDisk
	Size           int32 `json:"size"`
	Returned_value int32 `json:"returned_value"`
}

type SocketData struct {
	Socket     string   `json:"socket,omitempty"`
	SocketType string   `json:"socket_type"`
	Src        string   `json:"src"`
	SrcPort    uint16   `json:"src_port"`
	Dst        string   `json:"dst"`
	DstPort    uint16   `json:"dst_port"`
	sock_saddr []uint64 `json:"-"`
	sock_daddr []uint64 `json:"-"`
}

type EventSocket struct {
	EventContext
	SocketData
}

type EventSocketSendRecv struct {
	EventSocket
	Size           int32 `json:"size"`
	Returned_value int32 `json:"returned_value,omitempty"`
}

type EventProcess struct {
	EventContext
	Child uint32 `json:"child,omitempty"`
}

func (sock *SocketData) generate_socket_id() {
	if sock.sock_saddr[0] < sock.sock_daddr[0] {
		sock.Socket = fmt.Sprintf("%s:%d-%s:%d", sock.Src, sock.SrcPort, sock.Dst, sock.DstPort)
	} else if sock.sock_daddr[0] < sock.sock_saddr[0] {
		sock.Socket = fmt.Sprintf("%s:%d-%s:%d", sock.Dst, sock.DstPort, sock.Src, sock.SrcPort)
	} else if sock.sock_saddr[1] < sock.sock_daddr[1] {
		sock.Socket = fmt.Sprintf("%s:%d-%s:%d", sock.Src, sock.SrcPort, sock.Dst, sock.DstPort)
	} else if sock.sock_daddr[1] < sock.sock_saddr[1] {
		sock.Socket = fmt.Sprintf("%s:%d-%s:%d", sock.Dst, sock.DstPort, sock.Src, sock.SrcPort)
	} else if sock.SrcPort < sock.DstPort {
		sock.Socket = fmt.Sprintf("%s:%d-%s:%d", sock.Src, sock.SrcPort, sock.Dst, sock.DstPort)
	} else {
		sock.Socket = fmt.Sprintf("%s:%d-%s:%d", sock.Dst, sock.DstPort, sock.Src, sock.SrcPort)
	}
}

func (ev *EventDisk) GetType() uint32 {
	return ev.Etype
}
func (ev *EventSocket) GetType() uint32 {
	return ev.Etype
}
func (ev *EventProcess) GetType() uint32 {
	return ev.Etype
}

func (ev *EventDisk) SetContext(context *EventContext) {
	ev.EventContext = *context
}
func (ev *EventSocket) SetContext(context *EventContext) {
	ev.EventContext = *context
}
func (ev *EventProcess) SetContext(context *EventContext) {
	ev.EventContext = *context
}

func (ev *EventSocket) SetSocket(socket *SocketData) {
	ev.SocketData = *socket
}

func (ev *EventDisk) ComputeMinhash()    {}
func (ev *EventSocket) ComputeMinhash()  {}
func (ev *EventProcess) ComputeMinhash() {}
func (ev *EventDiskWriteRead) ComputeMinhash() {
	ev.Signature = computeMinhash(ev.Msg, ev.MsgLen)
	ev.Msg = ""
	ev.MsgLen = 0
}
func (ev *EventSocketSendRecv) ComputeMinhash() {
	ev.Signature = computeMinhash(ev.Msg, ev.MsgLen)
	ev.Msg = ""
	ev.MsgLen = 0
}

func splitShingles(line string, char_ngram int) (shingles []string) {

	// Pad to ensure we get at least one shingle for short strings.
	var i int
	if len(line) < char_ngram {
		for i = len(line); i < char_ngram; i++ {
			line += " "
		}
	}
	for i := 0; i < len(line)-char_ngram+1; i++ {
		shingles = append(shingles, line[i:i+char_ngram])
	}
	return
}
func computeMinhash(msg string, msg_len uint64) []uint64 {
	if msg_len > 0 {
		//prepare minhash
		seed := int64(1)
		numHash := 10
		mh := minhashlsh.NewMinhash(seed, numHash)

		// split message into shingles
		shingles := splitShingles(msg, 5)
		for _, shingle := range shingles {
			mh.Push([]byte(shingle))
		}
		return mh.Signature()
	}

	return nil
}
