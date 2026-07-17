package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/urfave/cli/v3"
)

const (
	PEIFV = "peifv"
	DXEFV = "dxefv"

	PEIFV_SIZE = 0xE0000
	DXEFV_SIZE = 0xE80000

	refFlag     = "ref"
	inFlag      = "in"
	outFlag     = "out"
	fvFlag      = "fv"
	refSizeFlag = "refsize"
)

func main() {
	cmd := &cli.Command{
		Name:  "fvextract",
		Usage: "Extract a UEFI firmware volume (peifv/dxefv) from a QEMU memory dump",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     refFlag,
				Usage:    "firmware volume reference file",
				Required: true,
			},
			&cli.StringFlag{
				Name:     inFlag,
				Usage:    "dumped qemu memory",
				Required: true,
			},
			&cli.StringFlag{
				Name:     outFlag,
				Usage:    "extracted uefi firmware volume",
				Required: true,
			},
			&cli.StringFlag{
				Name:     fvFlag,
				Usage:    "firmware volume to extract [peifv, dxefv]",
				Required: true,
			},
			&cli.IntFlag{
				Name:  refSizeFlag,
				Usage: "number of bytes used to locate the reference volume in the dumped memory",
				Value: 256,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return run(cmd)
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run(cmd *cli.Command) error {
	volume := cmd.String(fvFlag)

	var volumeSize int
	switch {
	case strings.EqualFold(volume, PEIFV):
		volumeSize = PEIFV_SIZE
	case strings.EqualFold(volume, DXEFV):
		volumeSize = DXEFV_SIZE
	default:
		return fmt.Errorf("unknown firmware volume type %q; allowed: peifv, dxefv", volume)
	}

	refPath := cmd.String(refFlag)
	inputPath := cmd.String(inFlag)
	outputPath := cmd.String(outFlag)
	refSize := cmd.Int(refSizeFlag)

	ref, err := os.ReadFile(refPath)
	if err != nil {
		return fmt.Errorf("failed to read reference file: %w", err)
	}

	in, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	index := bytes.Index(in, ref[:refSize])
	if index == -1 {
		return fmt.Errorf("failed to find reference volume in dumped memory")
	}

	fmt.Printf("Index: %x\n", index)

	if err := os.WriteFile(outputPath, in[index:index+volumeSize], 0644); err != nil {
		return fmt.Errorf("failed to write output file %v: %w", outputPath, err)
	}
	return nil
}
