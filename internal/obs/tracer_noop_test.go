//go:build !perf

package obs

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNoopTracerAndRegistry(t *testing.T) {
	tracer := NewFuncTracer("ignored", nil)
	require.Equal(t, "", tracer.Name())
	require.False(t, tracer.ShouldSample())

	done := tracer.Trace()
	done()
	tracer.TraceSampled(true)()
	tracer.TraceNested(true)()
	require.Equal(t, TracerSnapshot{}, tracer.Snapshot())

	var buf bytes.Buffer
	GlobalRegistry.Register(tracer)
	GlobalRegistry.Report(&buf)
	require.Empty(t, buf.String())

	data, err := GlobalRegistry.ReportJSON()
	require.NoError(t, err)
	require.Equal(t, "{}", string(data))
	require.False(t, Enabled())
}
