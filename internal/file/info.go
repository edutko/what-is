package file

import (
	"errors"
	"fmt"
	"os"

	"whatis/internal/units"
)

type Info struct {
	Path        string
	Description string
	Attributes  map[string]string
	Children    []Info
}

var ErrNotRegularFile = errors.New("only regular files are supported")

var MaxReadSize = 128 * units.Megabyte

func Inspect(info Info) (Info, error) {
	s, err := os.Stat(info.Path)
	if err != nil {
		return info, fmt.Errorf("os.Stat: %w", err)
	}

	if s.Mode()&os.ModeType != 0 {
		return info, ErrNotRegularFile
	}

	var data []byte
	if s.Size() > MaxReadSize {
		f, err := os.Open(info.Path)
		if err != nil {
			return info, fmt.Errorf("os.Open(\"%s\"): %w", info.Path, err)
		}
		defer func() {
			_ = f.Close()
		}()
		data = make([]byte, MaxReadSize)
		_, err = f.Read(data)
		if err != nil {
			return info, fmt.Errorf("f.Read: %w", err)
		}
	} else {
		data, err = os.ReadFile(info.Path)
		if err != nil {
			return info, fmt.Errorf("os.ReadFile(\"%s\"): %w", info.Path, err)
		}
	}

	for _, parse := range candidateParsers(info, data) {
		finalInfo, err := parse(info, data)
		if err == nil {
			return finalInfo, nil
		}
	}

	return Info{Path: info.Path, Description: "unknown file type"}, nil
}

func candidateParsers(info Info, data []byte) []Parser {
	var ps []Parser
	for _, p := range filetypes {
		if p.MatchesName(info.Path) || p.MatchesMagic(data) {
			ps = append(ps, p.parser)
		}
	}
	return ps
}
