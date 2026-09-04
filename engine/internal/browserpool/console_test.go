package browserpool

import (
	"encoding/json"
	"testing"
)

func TestCDPCaptureCollectsConsoleAndExceptions(t *testing.T) {
	capture := newCDPCapture()
	params, _ := json.Marshal(map[string]interface{}{"type": "warning", "args": []map[string]interface{}{{"type": "string", "value": "deprecated API"}}})
	capture.handle(cdpMessage{Method: "Runtime.consoleAPICalled", Params: params})
	exception, _ := json.Marshal(map[string]interface{}{"exceptionDetails": map[string]interface{}{"text": "Uncaught", "url": "https://example.test/app.js", "lineNumber": 4, "exception": map[string]interface{}{"description": "TypeError: failed"}}})
	capture.handle(cdpMessage{Method: "Runtime.exceptionThrown", Params: exception})
	if len(capture.console) != 2 || capture.console[0].Level != "warning" || capture.console[1].Line != 5 {
		t.Fatalf("console events not captured: %+v", capture.console)
	}
}
