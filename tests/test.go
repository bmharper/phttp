package main

// When iterating on these tests, do:
//   make -s server && go run test.go

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"
)

const serverURl = "http://localhost:8080"
const externalServer = true // Enable this when debugging C++ code

type testFunc struct {
	runMode string
	f       func(cx *context)
}

func main() {
	launch := func(tf testFunc) bool {
		name := strings.Split(getFunctionName(tf.f), ".")[1]
		fmt.Printf("%-20s ", name)
		cx := newContext(tf.runMode)
		defer func() bool {
			cx.close()
			if r := recover(); r != nil {
				return false
			}
			return true
		}()
		tf.f(cx)
		fmt.Printf(" OK\n")
		return true
	}

	f, err := os.Create("profile.prof")
	if err != nil {
		log.Fatal(err)
	}
	err = pprof.StartCPUProfile(f)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		pprof.StopCPUProfile()
		f.Close()
	}()

	tests := []testFunc{
		{"--ListenAndRun", TestBasic},
	}

	for _, t := range tests {
		if !launch(t) {
			break
		}
	}
}

func getFunctionName(i interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}

func die(err error) {
	dieMsg(err.Error())
}

func dieMsg(err string) {
	fmt.Printf("Fatal: %v\n", err)
	panic(true)
}

func dieMsgf(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
	panic(true)
}

func dumpHeaders(resp *http.Response) {
	for k, v := range resp.Header {
		fmt.Printf("%v=%v\n", k, v)
	}
}

type context struct {
	server *exec.Cmd
	client http.Client
	stdout io.ReadCloser
}

func newContext(runMode string) *context {
	var err error
	c := &context{}
	if !externalServer {
		c.server = exec.Command("./server")
		c.server.Args = append(c.server.Args, runMode)
		c.server.Stdout = os.Stdout
		err = c.server.Start()
		if err != nil {
			die(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return c
}

func (c *context) close() {
	if c.server != nil {
		//fmt.Printf("Killing\n")
		c.server.Process.Signal(os.Kill)
		//c.server.Process.Kill()
		c.server.Wait()
		//fmt.Printf("Dead\n")
	}
}

func (c *context) getExpect(url string, statusCode int, responseBody string) {
	resp, err := c.client.Get(serverURl + url)
	//dumpHeaders(resp)
	if err != nil {
		dieMsgf("Fetching %v, expected %v '%v', but got %v", url, statusCode, responseBody, err)
	}
	if resp.StatusCode != statusCode {
		dieMsgf("Fetching %v, expected %v '%v', but got status code %v", url, statusCode, responseBody, resp.StatusCode)
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		dieMsgf("Fetching %v, expected %v '%v', but got %v when reading body", url, statusCode, responseBody, err)
	}
	if string(body) != responseBody {
		dieMsgf("Fetching %v, expected %v '%v', but got body '%v'", url, statusCode, responseBody, string(body))
	}
}

func TestBasic(cx *context) {
	for i := 0; i < 5000; i++ {
		fmt.Printf("Get %v - ", i)
		cx.getExpect("/", 200, "Hello")
		fmt.Printf("have %v\n", i)
	}
}
