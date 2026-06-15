package core

import (
	"fmt"
	"sync"
)

var (
	ErrLocked    = fmt.Errorf("can't acquire lock")
	ErrNotLocked = fmt.Errorf("can't unlock, as not currently locked")
)

var driversMu sync.RWMutex
var drivers = make(map[string]Driver)

type PluginRegistry struct {
	mu      sync.RWMutex
	drivers map[string]DriverFactory
}

type DriverFactory func(config map[string]any) (Driver, error)

func Register(name string, driver Driver) {
	driversMu.Lock()
	defer driversMu.Unlock()

	if driver == nil {
		panic("Register driver is nil")
	}

	if _, dup := drivers[name]; dup {
		panic("Driver already registered " + name)
	}

	drivers[name] = driver
}

func Open(name string, config map[string]any) (Driver, error) {
	driversMu.RLock()
	driver, exists := drivers[name]
	driversMu.RUnlock()

	if !exists {
		return nil, ErrPluginNotFound
	}

	return driver, nil
}

func List() []string {
	driversMu.RLock()
	defer driversMu.RUnlock()

	names := make([]string, 0, len(drivers))
	for n := range drivers {
		names = append(names, n)
	}

	return names
}
