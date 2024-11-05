package file

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/edutko/decipher/internal/units"
)

type Info struct {
	Path        string
	Size        int64
	Description string
	Attributes  []Attribute
	Children    []Info
}

type Attribute struct {
	Name  string
	Value string
}

var ErrNotRegularFile = errors.New("only regular files are supported")

var MaxReadSize = 128 * units.Megabyte

func Inspect(f *os.File) (Info, error) {
	info := Info{Path: f.Name()}

	s, err := f.Stat()
	if err != nil {
		return info, fmt.Errorf("os.Stat: %w", err)
	}

	if s.Mode().IsRegular() {
		info.Size = s.Size()
	}

	r := io.LimitReader(f, MaxReadSize)
	data, err := io.ReadAll(r)
	if err != nil {
		return info, fmt.Errorf("f.Read: %w", err)
	}

	for _, parse := range candidateParsers(info, data) {
		var i Info
		i, err := parse(info, data)
		if err != nil {
			log.Println(err)
		} else {
			return i, nil
		}
	}

	return info, nil
}

func candidateParsers(info Info, data []byte) []Parser {
	var ps []Parser
	for _, p := range filetypes {
		if p.MatchesName(info.Path) || p.MatchesMagic(data) || p.SmellsLike(info.Path, data, info.Size) {
			ps = append(ps, p.parser)
		}
	}
	return ps
}
