package profile

import (
	"fmt"
	"sort"
	"sync"
)

var registry = struct {
	sync.RWMutex
	plugins map[string]Plugin
}{
	plugins: make(map[string]Plugin),
}

func Register(plugin Plugin) {
	if plugin == nil {
		panic("profile: cannot register nil plugin")
	}
	id := plugin.ID()
	if id == "" {
		panic("profile: cannot register plugin with empty id")
	}
	registry.Lock()
	defer registry.Unlock()
	if _, exists := registry.plugins[id]; exists {
		panic("profile: duplicate plugin " + id)
	}
	registry.plugins[id] = plugin
}

func Get(id string) (Plugin, bool) {
	registry.RLock()
	defer registry.RUnlock()
	plugin, ok := registry.plugins[id]
	return plugin, ok
}

func MustGet(id string) (Plugin, error) {
	plugin, ok := Get(id)
	if !ok {
		return nil, fmt.Errorf("unknown profile %q", id)
	}
	return plugin, nil
}

func All() []Plugin {
	registry.RLock()
	defer registry.RUnlock()
	out := make([]Plugin, 0, len(registry.plugins))
	for _, plugin := range registry.plugins {
		out = append(out, plugin)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID() < out[j].ID()
	})
	return out
}

func AllMetadata() []Metadata {
	plugins := All()
	out := make([]Metadata, 0, len(plugins))
	for _, plugin := range plugins {
		out = append(out, plugin.Metadata())
	}
	return out
}
