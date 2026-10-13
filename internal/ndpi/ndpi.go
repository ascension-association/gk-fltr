// Package ndpi is a minimal cgo binding to nDPI's flow classification API.
//
// It links against the static libndpi.a produced by scripts/build-ndpi.sh
// (see cgo_<goarch>.go). A Module and the flows created from it must only be
// used from one goroutine at a time.
package ndpi

/*
#cgo CFLAGS: -O2
#cgo LDFLAGS: -lm

#include <stdlib.h>
#include <string.h>
#include <ndpi_api.h>

typedef struct {
	uint16_t master, app;
	uint16_t stack[NDPI_PROTOCOL_STACK_SIZE];
	uint16_t stack_num;
	int state;
	char ja4[37];
	char host[80];
} gk_result;

static void gk_fill(struct ndpi_flow_struct *f, ndpi_protocol *p, gk_result *r) {
	memset(r, 0, sizeof(*r));
	r->master = p->proto.master_protocol;
	r->app = p->proto.app_protocol;
	r->stack_num = p->protocol_stack.protos_num;
	if (r->stack_num > NDPI_PROTOCOL_STACK_SIZE)
		r->stack_num = NDPI_PROTOCOL_STACK_SIZE;
	memcpy(r->stack, p->protocol_stack.protos, r->stack_num * sizeof(r->stack[0]));
	r->state = p->state;
	// protos is a union: tls_quic is only valid for TLS-like flows.
	if (ndpi_stack_is_tls_like(&p->protocol_stack))
		strncpy(r->ja4, f->protos.tls_quic.ja4_client, sizeof(r->ja4) - 1);
	strncpy(r->host, f->host_server_name, sizeof(r->host) - 1);
}

static struct ndpi_detection_module_struct *gk_init(int license) {
	struct ndpi_detection_module_struct *m =
		ndpi_init_detection_module(NULL, (enum ndpi_license_type)license);
	if (m == NULL)
		return NULL;
	if (ndpi_finalize_initialization(m) != 0) {
		ndpi_exit_detection_module(m);
		return NULL;
	}
	return m;
}

static struct ndpi_flow_struct *gk_flow_new(void) {
	struct ndpi_flow_struct *f = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
	if (f != NULL)
		memset(f, 0, SIZEOF_FLOW_STRUCT);
	return f;
}

static void gk_process(struct ndpi_detection_module_struct *m, struct ndpi_flow_struct *f,
		const unsigned char *pkt, unsigned short len, uint64_t ts_ms,
		unsigned char dir, gk_result *r) {
	struct ndpi_flow_input_info in = {
		.in_pkt_dir = dir,
		.seen_flow_beginning = NDPI_FLOW_BEGINNING_UNKNOWN,
	};
	ndpi_protocol p = ndpi_detection_process_packet(m, f, pkt, len, ts_ms, &in);
	gk_fill(f, &p, r);
}

// gk_proto_info returns the category and breed names of protocol id.
static void gk_proto_info(struct ndpi_detection_module_struct *m, u_int16_t id,
		const char **category, const char **breed) {
	ndpi_protocol p;
	memset(&p, 0, sizeof(p));
	p.proto.app_protocol = id;
	*category = ndpi_category_get_name(m, ndpi_get_proto_category(m, p));
	*breed = ndpi_get_proto_breed_name(ndpi_get_proto_breed(m, id));
}

static void gk_giveup(struct ndpi_detection_module_struct *m, struct ndpi_flow_struct *f, gk_result *r) {
	ndpi_protocol p = ndpi_detection_giveup(m, f);
	gk_fill(f, &p, r);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"
)

// License selects which nDPI dissectors are enabled (nDPI >= 6.0).
// See README.license.md in the nDPI source.
type License int

const (
	LicenseNotForProfit  License = C.NDPI_LICENSE_NOT_FOR_PROFIT_LGPL
	LicenseForProfitLGPL License = C.NDPI_LICENSE_FOR_PROFIT_LGPL
	LicenseForProfitDual License = C.NDPI_LICENSE_FOR_PROFIT_DUAL_LICENSE
)

// ParseLicense parses the -ndpi-license flag value.
func ParseLicense(s string) (License, error) {
	switch s {
	case "not-for-profit":
		return LicenseNotForProfit, nil
	case "for-profit-lgpl":
		return LicenseForProfitLGPL, nil
	case "for-profit-dual":
		return LicenseForProfitDual, nil
	}
	return 0, fmt.Errorf("unknown nDPI license %q (want not-for-profit, for-profit-lgpl or for-profit-dual)", s)
}

// Direction of a packet relative to the flow's initiator.
type Direction uint8

const (
	DirUnknown        Direction = C.NDPI_IN_PKT_DIR_UNKNOWN
	DirClientToServer Direction = C.NDPI_IN_PKT_DIR_C_TO_S
	DirServerToClient Direction = C.NDPI_IN_PKT_DIR_S_TO_C
)

// State is nDPI's classification state for a flow.
type State int

const (
	StateInspecting State = C.NDPI_STATE_INSPECTING
	StatePartial    State = C.NDPI_STATE_PARTIAL
	StateMonitoring State = C.NDPI_STATE_MONITORING
	StateClassified State = C.NDPI_STATE_CLASSIFIED
)

// Final reports whether nDPI considers the classification settled.
func (s State) Final() bool { return s == StateMonitoring || s == StateClassified }

// Result is the classification of a flow after a packet.
type Result struct {
	Master, App uint16
	Stack       []uint16
	State       State
	JA4         string // JA4 client fingerprint (TLS/QUIC flows only)
	Host        string // SNI / HTTP host / DNS query name
}

// Has reports whether id appears anywhere in the classification.
func (r Result) Has(id uint16) bool {
	if id == 0 {
		return false
	}
	if r.Master == id || r.App == id {
		return true
	}
	for _, p := range r.Stack {
		if p == id {
			return true
		}
	}
	return false
}

// Module is an nDPI detection module.
type Module struct {
	m *C.struct_ndpi_detection_module_struct
}

// Flow is per-connection nDPI state.
type Flow struct {
	f *C.struct_ndpi_flow_struct
}

// New initializes a detection module with all protocols enabled.
func New(license License) (*Module, error) {
	m := C.gk_init(C.int(license))
	if m == nil {
		return nil, errors.New("ndpi: initializing detection module failed")
	}
	return &Module{m: m}, nil
}

// Close frees the module. Flows must be freed first.
func (m *Module) Close() {
	if m.m != nil {
		C.ndpi_exit_detection_module(m.m)
		m.m = nil
	}
}

// ProtoID returns the ID of the protocol called name (case-insensitive).
func (m *Module) ProtoID(name string) (uint16, bool) {
	cs := C.CString(name)
	defer C.free(unsafe.Pointer(cs))
	id := uint16(C.ndpi_get_proto_by_name(m.m, cs))
	return id, id != C.NDPI_PROTOCOL_UNKNOWN
}

// ProtoName returns the name of protocol id.
func (m *Module) ProtoName(id uint16) string {
	return C.GoString(C.ndpi_get_proto_name(m.m, C.u_int16_t(id)))
}

// Describe renders a classification like "TLS.YouTube".
func (m *Module) Describe(r Result) string {
	switch {
	case r.Master != 0 && r.App != 0 && r.Master != r.App:
		return m.ProtoName(r.Master) + "." + m.ProtoName(r.App)
	case r.App != 0:
		return m.ProtoName(r.App)
	default:
		return m.ProtoName(r.Master)
	}
}

// ProtoInfo describes a protocol nDPI can detect.
type ProtoInfo struct {
	ID       uint16
	Name     string // e.g. "Instagram"
	Category string // e.g. "SocialNetwork"
	Breed    string // e.g. "Fun", "Safe", "Unsafe"
}

// Protocols lists the protocols nDPI can detect.
func (m *Module) Protocols() []ProtoInfo {
	var ps []ProtoInfo
	n := uint(C.ndpi_get_num_protocols(m.m))
	for id := uint(1); id < n && id <= 0xffff; id++ {
		name := C.ndpi_get_proto_by_id(m.m, C.u_int(id))
		if name == nil || *name == 0 {
			continue
		}
		var cat, breed *C.char
		C.gk_proto_info(m.m, C.u_int16_t(id), &cat, &breed)
		ps = append(ps, ProtoInfo{ID: uint16(id), Name: C.GoString(name), Category: C.GoString(cat), Breed: C.GoString(breed)})
	}
	return ps
}

// NewFlow allocates flow state. It must be released with Free.
func (m *Module) NewFlow() *Flow {
	f := C.gk_flow_new()
	if f == nil {
		return nil
	}
	return &Flow{f: f}
}

// Free releases the flow.
func (f *Flow) Free() {
	if f != nil && f.f != nil {
		C.ndpi_free_flow(f.f)
		f.f = nil
	}
}

// Process feeds one packet, starting at its IP header, into the flow.
func (m *Module) Process(f *Flow, pkt []byte, tsMillis uint64, dir Direction) Result {
	if len(pkt) == 0 {
		return Result{}
	}
	if len(pkt) > 0xffff {
		pkt = pkt[:0xffff]
	}
	var r C.gk_result
	C.gk_process(m.m, f.f, (*C.uchar)(unsafe.Pointer(&pkt[0])), C.ushort(len(pkt)),
		C.uint64_t(tsMillis), C.uchar(dir), &r)
	return convert(&r)
}

// GiveUp returns nDPI's best guess for a flow it has not classified yet.
func (m *Module) GiveUp(f *Flow) Result {
	var r C.gk_result
	C.gk_giveup(m.m, f.f, &r)
	return convert(&r)
}

func convert(r *C.gk_result) Result {
	res := Result{
		Master: uint16(r.master),
		App:    uint16(r.app),
		State:  State(r.state),
		JA4:    strings.ToLower(C.GoString(&r.ja4[0])),
		Host:   C.GoString(&r.host[0]),
	}
	for i := 0; i < int(r.stack_num); i++ {
		res.Stack = append(res.Stack, uint16(r.stack[i]))
	}
	return res
}
