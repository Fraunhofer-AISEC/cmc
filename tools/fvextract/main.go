package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"strings"
)

const (
	PEIFV = "peifv"
	DXEFV = "dxefv"

	PEIFV_SIZE = 0xE0000
	DXEFV_SIZE = 0xE80000
)

func main() {

	refFile := flag.String("ref", "", "firmware volume reference file")
	inputFile := flag.String("in", "", "dumped qemu memory")
	outputFile := flag.String("out", "", "extracted uefi firmware volume")
	volume := flag.String("fv", "", "firmware volume to extract [peifv, dxefv]")
	refSize := flag.Int("refsize", 256, "This number of bytes will be used to find the reference volume in the dumped memory")
	flag.Parse()

	if *inputFile == "" {
		fmt.Println("Input file not specified")
		flag.Usage()
		return
	}
	if *outputFile == "" {
		fmt.Println("Output file not specified")
		flag.Usage()
		return
	}
	if *refFile == "" {
		fmt.Println("Reference file not specified")
		flag.Usage()
	}

	var volumeSize int
	if strings.EqualFold(*volume, PEIFV) {
		volumeSize = PEIFV_SIZE
	} else if strings.EqualFold(*volume, DXEFV) {
		volumeSize = DXEFV_SIZE
	} else {
		fmt.Printf("Unknown firmware volume type %q. Allowed: peifv, dxefv\n", *volume)
		return
	}

	ref, err := os.ReadFile(*refFile)
	if err != nil {
		fmt.Printf("Failed to read reference file: %v\n", err)
		return
	}

	in, err := os.ReadFile(*inputFile)
	if err != nil {
		fmt.Printf("Failed to read input file: %v\n", err)
		return
	}

	index := bytes.Index(in, ref[:*refSize])
	if index == -1 {
		fmt.Printf("Failed to find index\n")
		return
	}

	fmt.Printf("Index: %x\n", index)

	err = os.WriteFile(*outputFile, in[index:index+volumeSize], 0644)
	if err != nil {
		fmt.Printf("Failed to write output file %v: %v\n", outputFile, err)
		return
	}
}
