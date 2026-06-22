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

func Register(name string, driver Driver) {
	driversMu.Lock()
	defer driversMu.Unlock()

	if driver == nil {
		panic("driver is nil")
	}

	if _, dup := drivers[name]; dup {
		panic("Driver already registered " + name)
	}

	drivers[name] = driver
}

func Open(name string, config *Config) (Driver, error) {
	driversMu.RLock()
	driver, exists := drivers[name]
	driversMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("\"%s\" %w (forgotten import?)", name, ErrPluginNotFound)
	}

	return driver.Open(config)
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
