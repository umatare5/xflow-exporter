package collector

import (
	"testing"

	"github.com/umatare5/xflow-exporter/internal/config"
)

func testConfig() *config.Config {
	return &config.Config{
		Web: config.Web{
			ListenAddress: config.DefaultListenAddress,
			ListenPort:    config.DefaultListenPort,
			TelemetryPath: config.DefaultTelemetryPath,
		},
		Log: config.Log{
			Level:  config.DefaultLogLevel,
			Format: config.DefaultLogFormat,
		},
	}
}

func TestNewCollector(t *testing.T) {
	t.Parallel()

	c := NewCollector(testConfig())
	if c == nil {
		t.Fatal("NewCollector() returned nil")
	}
	if c.Registry() == nil {
		t.Fatal("Registry() returned nil")
	}
}

func TestCollector_RegistryIndependence(t *testing.T) {
	t.Parallel()

	first := NewCollector(testConfig())
	second := NewCollector(testConfig())
	if first.Registry() == second.Registry() {
		t.Error("two collectors share one registry, want independent registries")
	}
}

func TestCollector_RegisterBuildInfo(t *testing.T) {
	t.Parallel()

	c := NewCollector(testConfig())
	c.RegisterBuildInfo("1.2.3")

	families, err := c.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v, want nil", err)
	}

	found := false
	for _, family := range families {
		if family.GetName() != "xflow_build_info" {
			continue
		}
		found = true

		metrics := family.GetMetric()
		if len(metrics) != 1 {
			t.Fatalf("xflow_build_info has %d series, want 1", len(metrics))
		}
		if got := metrics[0].GetGauge().GetValue(); got != 1 {
			t.Errorf("xflow_build_info value = %v, want 1", got)
		}

		labels := metrics[0].GetLabel()
		if len(labels) != 1 || labels[0].GetName() != "version" || labels[0].GetValue() != "1.2.3" {
			t.Errorf("xflow_build_info labels = %v, want version=1.2.3", labels)
		}
	}
	if !found {
		t.Error("xflow_build_info was not registered")
	}
}

func TestCollector_RegisterSystemCollectors_Disabled(t *testing.T) {
	t.Parallel()

	c := NewCollector(testConfig())
	c.RegisterSystemCollectors()

	families, err := c.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v, want nil", err)
	}
	if len(families) != 0 {
		t.Errorf("registry carries %d families with system collectors disabled, want 0", len(families))
	}
}

func TestCollector_RegisterSystemCollectors_Enabled(t *testing.T) {
	t.Parallel()

	cfg := testConfig()
	cfg.InternalCollector.EnableGoCollector = true
	cfg.InternalCollector.EnableProcessCollector = true

	c := NewCollector(cfg)
	c.RegisterSystemCollectors()

	families, err := c.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v, want nil", err)
	}

	hasGoMetric := false
	for _, family := range families {
		if family.GetName() == "go_goroutines" {
			hasGoMetric = true
		}
	}
	if !hasGoMetric {
		t.Error("go_goroutines is absent, want the Go collector registered")
	}
}

func TestCollector_Setup(t *testing.T) {
	t.Parallel()

	c := NewCollector(testConfig())
	c.Setup("test-version")

	families, err := c.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v, want nil", err)
	}

	// With every optional collector disabled, build info is the only family.
	if len(families) != 1 || families[0].GetName() != "xflow_build_info" {
		names := make([]string, 0, len(families))
		for _, family := range families {
			names = append(names, family.GetName())
		}
		t.Errorf("Setup() registered %v, want only xflow_build_info", names)
	}
}
