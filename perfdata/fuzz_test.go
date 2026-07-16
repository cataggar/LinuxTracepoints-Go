package perfdata

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func FuzzOpenMetadata(f *testing.F) {
	seed := seekFixture(binary.LittleEndian, sampleRecord(binary.LittleEndian, 77, 1, 2, 3, 4, testPayload(binary.LittleEndian)), tracingBlob(binary.LittleEndian, 8, testFormat), 77)
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		r, err := Open(bytes.NewReader(data), int64(len(data)), Options{Limits: Limits{MaxFeatureBytes: 1 << 20, MaxMetadataBytes: 2 << 20}})
		if err == nil {
			_, _ = r.Next()
			_ = r.Close()
		}
	})
}

func FuzzPipeRecords(f *testing.F) {
	f.Add(pipeFixture(binary.LittleEndian, sampleRecord(binary.LittleEndian, 77, 1, 2, 3, 4, testPayload(binary.LittleEndian)), tracingBlob(binary.LittleEndian, 8, testFormat), 77))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		r, err := OpenPipe(bytes.NewReader(data), Options{Limits: Limits{MaxFeatureBytes: 1 << 20, MaxMetadataBytes: 2 << 20}})
		if err != nil {
			return
		}
		for i := 0; i < 64; i++ {
			_, err = r.Next()
			if err != nil {
				if err == io.EOF {
				}
				break
			}
		}
	})
}

func FuzzSampleDecode(f *testing.F) {
	f.Add(testPayload(binary.LittleEndian))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65535 {
			t.Skip()
		}
		sample := sampleRecord(binary.LittleEndian, 77, 1, 2, 3, 4, raw)
		r, err := OpenPipe(bytes.NewReader(pipeFixture(binary.LittleEndian, sample, tracingBlob(binary.LittleEndian, 8, testFormat), 77)), Options{})
		if err == nil {
			_, _ = r.Next()
		}
	})
}
