package main_test

import (
	"bytes"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestBletchley(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CLI Suite")
}

var (
	cliTestDirectory string
	cliBinary        string
	privateKeyPath   string
	publicKeyPath    string
)

func run(arguments ...string) (stdout, stderr string, err error) {
	return runWithStdin("", arguments...)
}

func runWithStdin(stdin string, arguments ...string) (stdout, stderr string, err error) {
	stdoutBytes, stderrBytes := &bytes.Buffer{}, &bytes.Buffer{}
	cmd := exec.Command(cliBinary, arguments...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = stdoutBytes, stderrBytes, strings.NewReader(stdin)
	err = cmd.Run()
	stdout, stderr = stdoutBytes.String(), stderrBytes.String()

	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			panic(err)
		}
	}

	return
}

func compileCLI() {
	path, err := exec.LookPath("go")
	if err != nil {
		panic(err)
	}

	cmd := exec.Command(path, "build", "-o", cliBinary, "main.go")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		panic(err)
	}
}

func newTempFilename(prefix string) string {
	f, err := ioutil.TempFile("", prefix)
	if err != nil {
		panic(err)
	}
	f.Close()
	return f.Name()
}

var _ = BeforeSuite(func() {
	var err error
	cliTestDirectory, err = ioutil.TempDir("", "")
	if err != nil {
		panic(err)
	}
	cliBinary = path.Join(cliTestDirectory, "bletchley-cli-test")

	compileCLI()
})

var _ = AfterSuite(func() {
	os.RemoveAll(cliTestDirectory)
})

var _ = BeforeEach(func() {
	privateKeyPath = newTempFilename("private-key")
	publicKeyPath = newTempFilename("public-key")
})

var _ = AfterEach(func() {
	os.Remove(privateKeyPath)
	os.Remove(publicKeyPath)
})
