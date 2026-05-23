package cache

import (
	"errors"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
)

const cacheBackendEnv = "MOSDNS_CACHE_BACKEND"
const rustGoMirrorEnv = "MOSDNS_RUST_CACHE_GO_MIRROR"

var errRustBridgeUnavailable = errors.New("rust cache bridge is unavailable in current build")

type cacheBackendBridge interface {
	Name() string
	LookupByKey(queryKey []byte, now time.Time) (*bridgeLookupResult, error)
	StoreByKey(queryKey []byte, response []byte, domainSet string, now time.Time) (bool, error)
	Flush() error
	ExportDump() ([]byte, error)
	ImportDump(payload []byte) error
	Close() error
}

type bridgeLookupState int

const (
	bridgeLookupMiss bridgeLookupState = iota
	bridgeLookupFresh
	bridgeLookupLazy
)

type bridgeLookupResult struct {
	State     bridgeLookupState
	Response  []byte
	DomainSet string
}

func initRustBridge(args *Args, logger *zap.Logger) (cacheBackendBridge, bool) {
	backend := strings.TrimSpace(strings.ToLower(os.Getenv(cacheBackendEnv)))
	if backend != "rust" {
		return nil, false
	}

	bridge, err := newRustBridge(args, logger)
	if err != nil {
		logger.Warn("failed to initialize rust cache runtime, falling back to go cache",
			zap.String("env", cacheBackendEnv),
			zap.Error(err),
		)
		return nil, false
	}

	return bridge, true
}

func isRustGoMirrorEnabled() bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(rustGoMirrorEnv)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
