//go:build linux && cgo && mosdns_rust_cache

package cache

/*
#cgo CFLAGS: -I${SRCDIR}/../../../rust/cache-core/include
#cgo LDFLAGS: -L${SRCDIR}/../../../rust/cache-core/target/release -lmosdns_cache_core -ldl -lm -lpthread
#include "mosdns_cache_core.h"
*/
import "C"
import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	"go.uber.org/zap"
)

type rustBridge struct {
	handle unsafe.Pointer
}

func newRustBridge(args *Args, _ *zap.Logger) (cacheBackendBridge, error) {
	if rc := int(C.mosdns_cache_runtime_ping()); rc != 0 {
		return nil, fmt.Errorf("runtime ping failed: %d", rc)
	}

	excludeBlob := strings.Join(args.ExcludeIPs, " ")
	excludeBytes := []byte(excludeBlob)
	var excludePtr *C.uchar
	if len(excludeBytes) > 0 {
		excludePtr = (*C.uchar)(unsafe.Pointer(&excludeBytes[0]))
	}

	handle := C.mosdns_cache_new(
		C.ulonglong(args.Size),
		C.uint(args.LazyCacheTTL),
		boolToCUchar(args.EnableECS),
		excludePtr,
		C.ulonglong(len(excludeBytes)),
	)
	if handle == nil {
		return nil, fmt.Errorf("mosdns_cache_new returned nil handle")
	}

	return &rustBridge{handle: handle}, nil
}

func (r *rustBridge) Name() string {
	return C.GoString(C.mosdns_cache_runtime_version())
}

func (r *rustBridge) LookupByKey(queryKey []byte, now time.Time) (*bridgeLookupResult, error) {
	queryKeyPtr, queryKeyLen := sliceToCPtr(queryKey)

	res := C.mosdns_cache_lookup_by_key(
		r.handle,
		queryKeyPtr,
		queryKeyLen,
		C.longlong(now.Unix()),
	)
	if int(res.status) != 0 {
		return nil, fmt.Errorf("rust lookup-by-key failed with status %d", int(res.status))
	}

	response := copyAndFreeCBuffer(res.response_ptr, res.response_len)
	domainSet := string(copyAndFreeCBuffer(res.domain_set_ptr, res.domain_set_len))

	state := bridgeLookupMiss
	switch int(res.state) {
	case 1:
		state = bridgeLookupFresh
	case 2:
		state = bridgeLookupLazy
	}

	return &bridgeLookupResult{
		State:     state,
		Response:  response,
		DomainSet: domainSet,
	}, nil
}

func (r *rustBridge) StoreByKey(queryKey []byte, response []byte, domainSet string, now time.Time) (bool, error) {
	queryKeyPtr, queryKeyLen := sliceToCPtr(queryKey)
	responsePtr, responseLen := sliceToCPtr(response)
	domainSetBytes := []byte(domainSet)
	domainSetPtr, domainSetLen := sliceToCPtr(domainSetBytes)

	rc := int(C.mosdns_cache_store_by_key(
		r.handle,
		queryKeyPtr,
		queryKeyLen,
		responsePtr,
		responseLen,
		domainSetPtr,
		domainSetLen,
		C.longlong(now.Unix()),
	))
	if rc < 0 {
		return false, fmt.Errorf("rust store-by-key failed with status %d", rc)
	}
	return rc > 0, nil
}

func (r *rustBridge) Close() error {
	if r.handle != nil {
		C.mosdns_cache_free(r.handle)
		r.handle = nil
	}
	return nil
}

func (r *rustBridge) Flush() error {
	if r.handle == nil {
		return nil
	}
	rc := int(C.mosdns_cache_flush(r.handle))
	if rc != 0 {
		return fmt.Errorf("rust flush failed with status %d", rc)
	}
	return nil
}

func (r *rustBridge) ExportDump() ([]byte, error) {
	if r.handle == nil {
		return nil, fmt.Errorf("rust bridge handle is nil")
	}
	res := C.mosdns_cache_export_dump(r.handle)
	if int(res.status) != 0 {
		return nil, fmt.Errorf("rust export dump failed with status %d", int(res.status))
	}
	return copyAndFreeCBuffer(res.ptr, res.len), nil
}

func (r *rustBridge) ImportDump(payload []byte) error {
	if r.handle == nil {
		return fmt.Errorf("rust bridge handle is nil")
	}
	ptr, length := sliceToCPtr(payload)
	rc := int(C.mosdns_cache_import_dump(r.handle, ptr, length))
	if rc != 0 {
		return fmt.Errorf("rust import dump failed with status %d", rc)
	}
	return nil
}

func boolToCUchar(v bool) C.uchar {
	if v {
		return 1
	}
	return 0
}

func sliceToCPtr(b []byte) (*C.uchar, C.ulonglong) {
	if len(b) == 0 {
		return nil, 0
	}
	return (*C.uchar)(unsafe.Pointer(&b[0])), C.ulonglong(len(b))
}

func copyAndFreeCBuffer(ptr *C.uchar, length C.ulonglong) []byte {
	if ptr == nil || length == 0 {
		return nil
	}
	goBytes := C.GoBytes(unsafe.Pointer(ptr), C.int(length))
	C.mosdns_cache_free_buffer(ptr, length)
	return goBytes
}
