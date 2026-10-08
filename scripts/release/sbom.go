package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type module struct{ Path, Version, Dir, Sum string }
type component struct {
	Type    string `json:"type"`
	BOMRef  string `json:"bom-ref"`
	Group   string `json:"group,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
}
type bom struct {
	BOMFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber"`
	Version      int            `json:"version"`
	Metadata     map[string]any `json:"metadata"`
	Components   []component    `json:"components"`
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: sbom.go OUTPUT")
	}
	out, err := os.Create(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer out.Close()
	cmd := exec.Command("go", "list", "-m", "-json", "all")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		panic(err)
	}
	if err := cmd.Start(); err != nil {
		panic(err)
	}
	dec := json.NewDecoder(bufio.NewReader(stdout))
	components := []component{}
	for {
		var m module
		err := dec.Decode(&m)
		if errors.Is(err, os.ErrClosed) {
			break
		}
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			panic(err)
		}
		if m.Path == "" {
			continue
		}
		group, name := m.Path, m.Path
		if i := strings.LastIndex(m.Path, "/"); i >= 0 {
			group, name = m.Path[:i], m.Path[i+1:]
		}
		components = append(components, component{Type: "library", BOMRef: "pkg:golang/" + m.Path + "@" + m.Version, Group: group, Name: name, Version: m.Version, PURL: "pkg:golang/" + m.Path + "@" + m.Version})
	}
	if err := cmd.Wait(); err != nil {
		panic(err)
	}
	b := bom{BOMFormat: "CycloneDX", SpecVersion: "1.5", SerialNumber: "urn:uuid:aegisllm-release-sbom", Version: 1, Metadata: map[string]any{"timestamp": time.Unix(0, 0).UTC().Format(time.RFC3339), "tools": []any{map[string]string{"vendor": "AegisLLM", "name": "offline-go-sbom", "version": "1"}}}, Components: components}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(b); err != nil {
		panic(err)
	}
	if b.BOMFormat != "CycloneDX" || b.SpecVersion != "1.5" || len(b.Components) == 0 {
		panic(fmt.Sprintf("invalid SBOM: %+v", b))
	}
}
