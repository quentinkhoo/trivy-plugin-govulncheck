package image

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

// Respect the OS's temp directory instead
var tmpDirName string = "trivy-govulncheck-*"
var tmpDir string

// Given an image and a list of target binaries, extract those binaries from the image
func ExtractBinaries(ref string, targets []string) (map[string]string, error) {
	img, err := crane.Pull(ref)
	if err != nil {
		return nil, fmt.Errorf("pulling image: %w", err)
	}

	tmpDir, err = os.MkdirTemp("", tmpDirName)
	if err != nil {
		return nil, fmt.Errorf("creating temp dir: %w", err)
	}

	// https://labs.iximiuz.com/tutorials/container-image-from-scratch
	// sometimes trivy reports gobinary targets with a leading "/", but the tarball entries don't have it
	// so we create a set of the targets with the leading "/" trimmed to make it easier to match against the tarball entries
	// also we make a map so we can do an O(1) lookup instead of O(n)
	targetSet := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		targetSet[strings.TrimPrefix(target, "/")] = struct{}{}
	}

	// Flatten the image that will be in tar format, then extract the binaries from the tarball
	fs := mutate.Extract(img)
	defer fs.Close()

	// Walk through the tarball and extract any entries that match our targets
	// https://medium.com/learning-the-go-programming-language/working-with-compressed-tar-files-in-go-e6fe9ce4f51d
	tr := tar.NewReader(fs)
	extractedBinaries := make(map[string]string)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tarball: %w", err)
		}

		// Clean the header name so its of the targetSet naming convention
		cleanPath := path.Clean(header.Name)
		cleanPath = strings.TrimPrefix(cleanPath, "/")

		// Check if the cleaned header name is in our target set, if not skip it
		if _, ok := targetSet[cleanPath]; !ok {
			continue
		}

		// If it is in the target set, extract it to our temp directory
		localName := strings.ReplaceAll(cleanPath, "/", "_")
		localPath := path.Join(tmpDir, localName)
		outFile, err := os.Create(localPath)
		if err != nil {
			return nil, fmt.Errorf("creating file: %w", err)
		}

		if _, err := io.Copy(outFile, tr); err != nil {
			outFile.Close()
			return nil, fmt.Errorf("writing file: %w", err)
		}
		outFile.Close()

		// We need to make the binary executable for govulncheck to be able to analyze it
		os.Chmod(localPath, 0755)
		extractedBinaries[cleanPath] = localPath
	}

	return extractedBinaries, nil
}

func CleanupTempDir() {
	os.RemoveAll(tmpDir)
}