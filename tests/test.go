package main

// When iterating on these tests:
// Unix:
//   make -s -j build/server.exe && go run tests/test.go
//
// Windows
//   wsl WINDOWS=1 make -s -j build/server.exe && go run tests/test.go
//
// To benchmark with ab:
//   make server && ./server --concurrent
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
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const serverURL = "http://localhost:8080"
const serverURL_WS = "ws://localhost:8080"
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
		{"--concurrent", TestConcurrency},
		{"--concurrent", TestWebSocket},
		{"--concurrent", TestBackoff},
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
		// I don't know how else to send a kill signal to a windows process, so we reserve
		// a special HTTP message for that.
		c.client.Get(serverURL + "/kill")
		time.Sleep(100 * time.Millisecond)
		c.server.Process.Signal(os.Kill)
		//c.server.Process.Kill()
		c.server.Wait()
		//fmt.Printf("Dead (exit code %v)\n", c.server.ProcessState.Success())
		if !c.server.ProcessState.Success() {
			dieMsgf("C++ server process exited with non-zero success code")
		}
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

func digits(num int) string {
	s := []byte{}
	for i := 0; i < num; i++ {
		s = append(s, '0'+byte(i%10))
	}
	return string(s)
}

func TestBasic(cx *context) {
	for i := 0; i < 5000; i++ {
		//fmt.Printf("Get %v - ", i)
		cx.getExpect("/", 200, "Hello")
		//fmt.Printf("have %v\n", i)
	}

	for num := 0; num < 1000000; num = int(float64(num)*1.1) + 1 {
		cx.getExpect(fmt.Sprintf("/digits?num=%v", num), 200, digits(num))
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

type WebSocket struct {
	id       int
	con      *websocket.Conn
	lastSent int
	lastRecv int
	numPongs int
}

func TestWebSocket(cx *context) {
	dial := websocket.Dialer{}
	socks := []*WebSocket{}

	n := 5 // keep this a prime number to make round-robinning easy
	for i := 0; i < n; i++ {
		con, _, err := dial.Dial(serverURL_WS, http.Header{})
		if err != nil {
			dieMsgf("Failed to connect to websocket: %v", err)
		}
		ws := &WebSocket{
			id:       i + 1,
			con:      con,
			lastSent: -1,
			lastRecv: -1,
			numPongs: 0,
		}
		pongHandler := func(appData string) error {
			expect := fmt.Sprintf("ping-%v", ws.id)
			if appData != expect {
				dieMsgf("Received unexpected pong (expect %v, received %v)", expect, appData)
			}
			ws.numPongs++
			return nil
		}
		con.SetPongHandler(pongHandler)
		socks = append(socks, ws)
	}

	done := make(chan bool)

	// These two don't need to be tied together. The server keeps sending messages until we kill it.
	numRecv := 1000
	numWrite := 1000

	// reader thread
	go func() {
		for i := 0; i < numRecv; i++ {
			if len(socks) == 0 {
				break
			}
			sock := socks[i%len(socks)]
			mtype, r, err := sock.con.NextReader()
			if err != nil {
				dieMsgf("Failed to get NextReader: %v", err)
			}
			if mtype != websocket.TextMessage {
				dieMsgf("Expected text message (1), but got: %v", mtype)
			}
			buf, err := ioutil.ReadAll(r)
			if err != nil {
				dieMsgf("Error reading from websocket: %v", err)
			}
			val, _ := strconv.ParseInt(string(buf), 10, 64)
			if int(val) < sock.lastRecv {
				dieMsgf("Server sent value smaller than previous (%v < %v)", val, sock.lastRecv)
			}
			sock.lastRecv = int(val)
			//fmt.Printf("Recv from %v: %v\n", sock.id, val)
		}
		done <- true
	}()

	// writer thread
	go func() {
		for i := 0; i < numWrite; i++ {
			sock := socks[i%len(socks)]
			var err error
			var w io.WriteCloser
			var msg string
			if i%13 == 0 {
				// Ping
				w, err = sock.con.NextWriter(websocket.PingMessage)
				if err != nil {
					dieMsgf("Error getting writer for ping: %v", err)
				}
				msg = fmt.Sprintf("ping-%v", sock.id)
			} else {
				// Text Message
				w, err = sock.con.NextWriter(websocket.TextMessage)
				if err != nil {
					dieMsgf("Error getting writer: %v", err)
				}
				sock.lastSent++
				msg = fmt.Sprintf("%v", sock.lastSent)
			}
			n, err := w.Write([]byte(msg))
			if err != nil || n != len(msg) {
				dieMsgf("Error writing to websocket (%v, %v)", err, n)
			}
			w.Close()
			//fmt.Printf("Sent to %v: %v\n", sock.id, sock.lastSent)
		}

		done <- true
	}()

	// wait for reader & writer to finish
	<-done
	<-done

	for i := 0; i < len(socks); i++ {
		// gracefactor is here to allow for less sent messages than numWrite / n, because some messages are pings, and
		// round robin might not reach all sockets equally.
		sock := socks[i]
		graceFactor := 3
		expectRecv := numWrite / (n * graceFactor)
		if sock.lastRecv < expectRecv {
			dieMsgf("Socket %v: Expected to receive at least %v from server, but only got %v", sock.id, expectRecv, sock.lastRecv)
		}
		if sock.numPongs == 0 {
			dieMsgf("Socket %v received no pongs", sock.id)
		}
		sock.con.Close()
	}
}

func TestBackoff(cx *context) {
	size := 1024 * 1024 * 1024
	req, err := http.NewRequest("GET", serverURL+fmt.Sprintf("/stream?bytes=%v", size), nil)
	if err != nil {
		dieMsgf("Failed to create request: %v", err)
	}
	resp, err := cx.client.Do(req)
	defer resp.Body.Close()
	mult := uint32(997)
	expect := uint32(0)
	buf := make([]byte, 4000, 0)
	offset := 0
	for i := 0; true; i++ {
		n, err := resp.Body.Read(buf)
		for j := 0; j < n; j++ {
			expect = (expect + 1) * mult
			if buf[j] != byte(expect&0xff) {
				dieMsgf("Byte %v wrong. Expected %v, but got %v", offset+j, expect&0xff, buf[j])
			}
		}
		offset += n
		fmt.Printf("recv %v/%v\n", offset, size)
		if i%100 == 0 {
			time.Sleep(1 * time.Second)
		}
	}
}
