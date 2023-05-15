package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/edutko/what-is/internal/file"
)

func main() {
	flag.Parse()

	f := flag.Arg(0)
	if f == "" {
		flag.Usage()
		os.Exit(1)
	}

	s, err := os.Stat(f)
	if err != nil {
		log.Fatalln(err)
	}

	if s.IsDir() {
		entries, err := os.ReadDir(f)
		if err != nil {
			log.Fatalln(err)
		}

		for _, e := range entries {
			if e.IsDir() {
				continue
			}

			p := filepath.Join(f, e.Name())
			info, err := file.Inspect(file.Info{Path: p})
			if err != nil {
				log.Printf("error processing file \"%s\": %v", p, err)
				continue
			}

			fmt.Printf("%s: ", info.Path)
			printInfo(info, 0)
		}
	} else {
		info, err := file.Inspect(file.Info{Path: f})
		if err != nil {
			log.Fatalln(err)
		}

		fmt.Println(info.Path)
		printInfo(info, 0)
	}
}

func printInfo(info file.Info, indent int) {
	indentStr := strings.Repeat(" ", indent)
	fmt.Printf("%s%s\n", indentStr, info.Description)
	for _, a := range info.Attributes {
		fmt.Printf("%s  %s: %s\n", indentStr, a.Name, a.Value)
	}
	for _, child := range info.Children {
		printInfo(child, indent+2)
	}
}
