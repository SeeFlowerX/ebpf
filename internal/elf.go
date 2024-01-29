package internal

import (
	"archive/zip"
	"debug/elf"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"strings"
)

type SafeELFFile struct {
	*elf.File
}

type ZipFileReaderAt struct {
	Data []byte
}

// NewSafeELFFile reads an ELF safely.
//
// Any panic during parsing is turned into an error. This is necessary since
// there are a bunch of unfixed bugs in debug/elf.
//
// https://github.com/golang/go/issues?q=is%3Aissue+is%3Aopen+debug%2Felf+in%3Atitle
func NewSafeELFFile(r io.ReaderAt) (safe *SafeELFFile, err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}

		safe = nil
		err = fmt.Errorf("reading ELF file panicked: %s", r)
	}()

	file, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}

	return &SafeELFFile{file}, nil
}

// OpenSafeELFFile reads an ELF from a file.
//
// It works like NewSafeELFFile, with the exception that safe.Close will
// close the underlying file.
func OpenSafeELFFile(path string) (safe *SafeELFFile, err error) {
	var file *elf.File
	defer func() {
		r := recover()
		if r == nil {
			return
		}

		safe = nil
		err = fmt.Errorf("reading ELF file panicked: %s", r)
	}()

	//check is there "!" in path
	if strings.Contains(path, "!") {
		file, err = OpenZipELFFile(path)
	} else {
		file, err = elf.Open(path)
	}
	if err != nil {
		return nil, err
	}

	return &SafeELFFile{file}, nil
}

func NewZipFileReaderAt(file fs.File) (*ZipFileReaderAt, error) {
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	return &ZipFileReaderAt{Data: data}, nil
}

func (z *ZipFileReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	// 检查偏移量是否超出范围
	if off >= int64(len(z.Data)) {
		return 0, io.EOF
	}

	// 读取数据
	n = copy(p, z.Data[off:])
	return n, nil
}

func OpenZipELFFile(path string) (elfFile *elf.File, err error) {
	// println("path", path)
	apkFileStr := strings.Split(path, "!")
	archive, err := zip.OpenReader(apkFileStr[0])
	if err != nil {
		return nil, err
	}
	f, err := archive.Open(strings.Split(apkFileStr[1], "@")[0])
	if err != nil {
		return nil, err
	}
	readerAt, err := NewZipFileReaderAt(f)
	if err != nil {
		return nil, err
	}
	elfFile, err = elf.NewFile(readerAt)
	if err != nil {
		return nil, err
	}
	return elfFile, nil
}

// Symbols is the safe version of elf.File.Symbols.
func (se *SafeELFFile) Symbols() (syms []elf.Symbol, err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}

		syms = nil
		err = fmt.Errorf("reading ELF symbols panicked: %s", r)
	}()

	syms, err = se.File.Symbols()
	return
}

// DynamicSymbols is the safe version of elf.File.DynamicSymbols.
func (se *SafeELFFile) DynamicSymbols() (syms []elf.Symbol, err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}

		syms = nil
		err = fmt.Errorf("reading ELF dynamic symbols panicked: %s", r)
	}()

	syms, err = se.File.DynamicSymbols()
	return
}

// SectionsByType returns all sections in the file with the specified section type.
func (se *SafeELFFile) SectionsByType(typ elf.SectionType) []*elf.Section {
	sections := make([]*elf.Section, 0, 1)
	for _, section := range se.Sections {
		if section.Type == typ {
			sections = append(sections, section)
		}
	}
	return sections
}
