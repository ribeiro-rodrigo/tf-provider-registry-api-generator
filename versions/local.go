package versions

import (
	"io"
	"os"
	"path/filepath"
)

func LoadFromLocal(path string) []string {
	var fileNames = []string{}

	err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		fileNames = append(fileNames, path)
		return nil
	})

	if err != nil {
		panic(err)
	}

	return fileNames
}

func NewFileReader(path string) (io.Reader, error) {
	file, err := os.Open(path)

	return file, err
}
