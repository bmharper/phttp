package main

// When iterating on these tests, do:
//   make -s server && go run test.go
// To benchmark with ab:
//   make server && ./server --Concurrent
//   ab -k -n 10000 -c 4 http://localhost:8080/echo-method

import (
	"bytes"
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

const serverURL = "http://localhost:8080"
const externalServer = false // Enable this when debugging C++ code
const enableProfile = false

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

	if enableProfile {
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
	}

	tests := []testFunc{
		{"--ListenAndRun", TestBasic},
		{"--ListenAndRun", TestMethods},
		{"--Concurrent", TestConcurrency},
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

func (c *context) getExpect(url string, expectCode int, expectBody string) {
	c.expect("GET", url, "", expectCode, expectBody)
}

func (c *context) expect(method, url, body string, expectCode int, expectBody string) {
	bodyReader := bytes.NewReader([]byte(body))
	req, err := http.NewRequest(method, serverURL+url, bodyReader)
	if err != nil {
		dieMsgf("Failed to create request: %v", err)
	}
	resp, err := c.client.Do(req)
	//dumpHeaders(resp)
	if err != nil {
		dieMsgf("Fetching %v, expected %v '%v', but got %v", url, expectCode, expectBody, err)
	}
	if resp.StatusCode != expectCode {
		dieMsgf("Fetching %v, expected %v '%v', but got status code %v", url, expectCode, expectBody, resp.StatusCode)
	}
	actualBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		dieMsgf("Fetching %v, expected %v '%v', but got %v when reading body", url, expectCode, expectBody, err)
	}
	if string(actualBody) != expectBody {
		dieMsgf("Fetching %v, expected %v '%v', but got body '%v'", url, expectCode, expectBody, string(actualBody))
	}
}

func TestBasic(cx *context) {
	for i := 0; i < 5000; i++ {
		//fmt.Printf("Get %v - ", i)
		cx.getExpect("/", 200, "Hello")
		//fmt.Printf("have %v\n", i)
	}
}

func TestMethods(cx *context) {
	cx.expect("DELETE", "/echo-method", "foo", 200, "DELETE-foo")
	cx.expect("GET", "/echo-method", "", 200, "GET-")
	cx.expect("HEAD", "/echo-method", "", 200, "")
	cx.expect("OPTIONS", "/echo-method", "", 200, "OPTIONS-")
	cx.expect("PATCH", "/echo-method", "foo", 200, "PATCH-foo")
	cx.expect("POST", "/echo-method", "foo", 200, "POST-foo")
	cx.expect("PUT", "/echo-method", "foo", 200, "PUT-foo")
	cx.expect("TRACE", "/echo-method", "", 200, "TRACE-")
}

func TestConcurrency(cx *context) {
	// I don't know why, but when I raise the concurrency level above 2, then the Go
	// HTTP client seems to close and reopen TCP sockets. I don't *think* it's something
	// that phttp is doing.
	// I get *much* higher numbers using "ab" to benchmark - 130k/s vs 30k/s (requests/s)
	nthread := 2
	done := make(chan bool, nthread)
	//start := time.Now()
	num := 5000
	for i := 0; i < nthread; i++ {
		myID := i
		go func() {
			for j := 0; j < num; j++ {
				if j%100 == 0 {
					//fmt.Printf("Thread %v, %v/%v\n", myID, j, num)
				}
				body := fmt.Sprintf("%v-%v", myID, j)
				cx.expect("POST", "/echo-method", body, 200, "POST-MT-"+body)
			}
			done <- true
		}()
	}
	for i := 0; i < nthread; i++ {
		<-done
	}
	//duration := time.Now().Sub(start)
	//fmt.Printf("\n  Requests per second: %v\n", int(float64(num*nthread)/duration.Seconds()))
}
