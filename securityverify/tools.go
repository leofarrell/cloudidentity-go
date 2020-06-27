package securityverify

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
)

func traceBody(result *http.Response) {
	if result != nil {
		body, berr := ioutil.ReadAll(result.Body)
		if berr != nil {
			svlog.Printf("Error parsing body")
		} else {
			svlog.Printf("Error response body: \n----\n%s\n----\n", body)
		}
	}
}

func outputPipe(intput interface{}) *io.PipeReader {
	r, w := io.Pipe()

	go func() {
		err := json.NewEncoder(w).Encode(intput)
		if err != nil {
			svlog.Print("Error encoding body(Programming error?", err.Error())
		}
		w.Close()

	}()
	return r
}
