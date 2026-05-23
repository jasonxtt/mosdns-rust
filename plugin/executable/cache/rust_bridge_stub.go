//go:build !(linux && cgo && mosdns_rust_cache)

package cache

import "go.uber.org/zap"

func newRustBridge(_ *Args, _ *zap.Logger) (cacheBackendBridge, error) {
	return nil, errRustBridgeUnavailable
}
