package https

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type httpParseResult struct {
	request  *http.Request
	response *http.Response
	body     []byte
	consumed int
}

func parseRequest(buf []byte) (*httpParseResult, bool, error) {
	if len(buf) == 0 {
		return nil, true, nil
	}
	reader := bytes.NewReader(buf)
	br := bufio.NewReader(reader)
	req, err := http.ReadRequest(br)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, true, nil
		}
		return nil, false, err
	}
	if req.Body != nil {
		defer req.Body.Close()
	}
	consumed := len(buf) - br.Buffered()
	bodyConsumed, body, needMore, err := consumeBody(req.ContentLength, req.TransferEncoding, buf[consumed:])
	if err != nil {
		return nil, false, err
	}
	if needMore {
		return nil, true, nil
	}
	consumed += bodyConsumed
	return &httpParseResult{request: req, body: body, consumed: consumed}, false, nil
}

func parseResponse(buf []byte) (*httpParseResult, bool, error) {
	if len(buf) == 0 {
		return nil, true, nil
	}
	reader := bytes.NewReader(buf)
	br := bufio.NewReader(reader)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, true, nil
		}
		return nil, false, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	consumed := len(buf) - br.Buffered()
	bodyConsumed, body, needMore, err := consumeBody(resp.ContentLength, resp.TransferEncoding, buf[consumed:])
	if err != nil {
		return nil, false, err
	}
	if needMore {
		return nil, true, nil
	}
	consumed += bodyConsumed
	return &httpParseResult{response: resp, body: body, consumed: consumed}, false, nil
}

func consumeBody(contentLen int64, transferEncoding []string, data []byte) (int, []byte, bool, error) {
	if hasChunked(transferEncoding) {
		consumed, complete, err := consumeChunked(data)
		if err != nil {
			return 0, nil, false, err
		}
		if !complete {
			return 0, nil, true, nil
		}
		body := append([]byte(nil), data[:consumed]...)
		return consumed, body, false, nil
	}
	if contentLen <= 0 {
		return 0, nil, false, nil
	}
	if int64(len(data)) < contentLen {
		return 0, nil, true, nil
	}
	body := append([]byte(nil), data[:contentLen]...)
	return int(contentLen), body, false, nil
}

func hasChunked(encodings []string) bool {
	for _, enc := range encodings {
		if strings.EqualFold(enc, "chunked") {
			return true
		}
	}
	return false
}

func consumeChunked(data []byte) (int, bool, error) {
	offset := 0
	for {
		lineEnd := bytes.Index(data[offset:], []byte("\r\n"))
		if lineEnd < 0 {
			return 0, false, nil
		}
		line := data[offset : offset+lineEnd]
		size, err := strconv.ParseInt(string(line), 16, 64)
		if err != nil {
			return 0, false, err
		}
		offset += lineEnd + 2
		if int64(len(data)-offset) < size+2 {
			return 0, false, nil
		}
		offset += int(size)
		if data[offset] != '\r' || data[offset+1] != '\n' {
			return 0, false, fmt.Errorf("invalid chunk terminator")
		}
		offset += 2
		if size == 0 {
			trailerEnd := bytes.Index(data[offset:], []byte("\r\n\r\n"))
			if trailerEnd < 0 {
				if len(data[offset:]) >= 2 && data[offset] == '\r' && data[offset+1] == '\n' {
					offset += 2
					return offset, true, nil
				}
				return 0, false, nil
			}
			offset += trailerEnd + 4
			return offset, true, nil
		}
	}
}
