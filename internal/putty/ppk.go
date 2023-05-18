package putty

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type PPK struct {
	Version      int
	Type         string
	Encryption   string
	Comment      string
	PublicKeyB64 string
}

// https://the.earth.li/~sgtatham/putty/0.78/htmldoc/AppendixC.html#ppk
func ParsePPKBytes(data []byte) (PPK, error) {
	p := PPK{}
	r := bufio.NewReader(bytes.NewReader(data))
	done := false
	for !done {
		l, err := r.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				done = true
			} else {
				return PPK{}, err
			}
		}

		parts := strings.SplitN(l, ":", 2)
		switch parts[0] {
		case "PuTTY-User-Key-File-2":
			p.Version = 2
			p.Type = strings.TrimSpace(parts[1])
		case "PuTTY-User-Key-File-3":
			p.Version = 3
			p.Type = strings.TrimSpace(parts[1])
		case "Encryption":
			p.Encryption = strings.TrimSpace(parts[1])
		case "Comment":
			p.Comment = strings.TrimSpace(parts[1])
		case "Public-Lines":
			count, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return PPK{}, fmt.Errorf("strconv.Atoi: %w", err)
			}
			p.PublicKeyB64, err = readLines(r, count)
			if err != nil {
				return PPK{}, fmt.Errorf("readLines: %w", err)
			}
		}
	}

	return p, nil
}

func readLines(r *bufio.Reader, count int) (string, error) {
	var lines []string
	for i := 0; i < count; i++ {
		l, err := r.ReadString('\n')
		lines = append(lines, strings.TrimSpace(l))
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			} else {
				return "", err
			}
		}
	}
	if len(lines) < count {
		return "", io.ErrUnexpectedEOF
	}
	return strings.Join(lines, ""), nil
}

func (p PPK) AsAuthorizedKey() []byte {
	return []byte(strings.Join([]string{p.Type, p.PublicKeyB64, p.Comment}, " "))
}
