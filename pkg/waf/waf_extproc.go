package waf

import (
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3"
	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	ttlcache "github.com/jellydator/ttlcache/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type serverExtProc struct {
	waf              coraza.WAF
	transactionCache *ttlcache.Cache[string, string]
}

var _ extproc.ExternalProcessorServer = &serverExtProc{}

// New creates a new ext_proc server.
func NewExtProc(wafInstance coraza.WAF, cache *ttlcache.Cache[string, string]) extproc.ExternalProcessorServer {
	return &serverExtProc{
		waf:              wafInstance,
		transactionCache: cache,
	}
}

// Check implements authorization's Check interface which performs authorization check based on the
// attributes associated with the incoming request.

func (s *serverExtProc) Process(stream extproc.ExternalProcessor_ProcessServer) error {

	// transactionID is received just on the first stream as part of request-headers. In
	// case it is not send or does not exist on the transaction ttl/map we should deny
	// the request
	var transactionID string
	ts := time.Now().Format(time.RFC3339Nano)

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			log.Printf("stream closed by client")
			return nil
		}
		if err != nil {
			if status.Code(err) == codes.Canceled {
				// This is expected behavior when Envoy closes the connection.
				// We can safely return nil to stop the loop.
				return nil
			}
			// Real errors
			return err
		}

		if h := req.GetRequestHeaders(); h != nil {
			out := fmt.Sprintf("%s REQUEST_HEADERS: %v\n", ts, h)
			log.Print(out)
		}

		switch v := req.Request.(type) {
		case *extproc.ProcessingRequest_RequestHeaders:
			h := v.RequestHeaders
			transactionID = getHeaderValue(h.Headers, "x-request-id")
			if transactionID == "" {
				return dropUnknownTransaction(stream)
			}

		case *extproc.ProcessingRequest_RequestBody:
			// Transaction ID MUST exist before moving to request body or any other part
			if transactionID == "" {
				return dropUnknownTransaction(stream)
			}

		case *extproc.ProcessingRequest_ResponseHeaders:
			// Transaction ID MUST exist before moving to request body or any other part
			if transactionID == "" {
				return dropUnknownTransaction(stream)
			}

		case *extproc.ProcessingRequest_ResponseBody:
			// Transaction ID MUST exist before moving to request body or any other part
			if transactionID == "" {
				return dropUnknownTransaction(stream)
			}
		}

		if h := req.GetRequestHeaders(); h != nil {
			out := fmt.Sprintf("%s REQUEST_HEADERS: %v\n", ts, h)
			log.Print(out)
		}
		if b := req.GetRequestBody(); b != nil {
			out := fmt.Sprintf("%s REQUEST_BODY (end_of_stream=%v, body_len=%d, body=%s)\n", ts, b.EndOfStream, len(b.GetBody()), string(b.Body))
			log.Print(out)
		}
		if t := req.GetRequestTrailers(); t != nil {
			out := fmt.Sprintf("%s REQUEST_TRAILERS: %v\n", ts, t)
			log.Print(out)
		}

		if rh := req.GetResponseHeaders(); rh != nil {
			out := fmt.Sprintf("%s RESPONSE_HEADERS: %v\n", ts, rh)
			log.Print(out)
		}
		if rb := req.GetResponseBody(); rb != nil {
			out := fmt.Sprintf("%s RESPONSE_BODY (end_of_stream=%v, body_len=%d, body=%s)\n", ts, rb.EndOfStream, len(rb.GetBody()), string(rb.Body))
			log.Print(out)
		}
		if rt := req.GetResponseTrailers(); rt != nil {
			out := fmt.Sprintf("%s RESPONSE_TRAILERS: %v\n", ts, rt)
			log.Print(out)
		}

		// CONTINUE processing without modification
		resp := &extproc.ProcessingResponse{
			Response: &extproc.ProcessingResponse_RequestHeaders{
				RequestHeaders: &extproc.HeadersResponse{},
			},
		}
		if req.GetRequestBody() != nil {
			resp = &extproc.ProcessingResponse{
				Response: &extproc.ProcessingResponse_RequestBody{
					RequestBody: &extproc.BodyResponse{},
				},
			}
		}
		if req.GetRequestTrailers() != nil {
			resp = &extproc.ProcessingResponse{
				Response: &extproc.ProcessingResponse_RequestTrailers{
					RequestTrailers: &extproc.TrailersResponse{},
				},
			}
		}
		if req.GetResponseHeaders() != nil {
			resp = &extproc.ProcessingResponse{
				Response: &extproc.ProcessingResponse_ResponseHeaders{
					ResponseHeaders: &extproc.HeadersResponse{},
				},
			}
		}
		if req.GetResponseBody() != nil {
			resp = &extproc.ProcessingResponse{
				Response: &extproc.ProcessingResponse_ResponseBody{
					ResponseBody: &extproc.BodyResponse{},
				},
			}
		}
		if req.GetResponseTrailers() != nil {
			resp = &extproc.ProcessingResponse{
				Response: &extproc.ProcessingResponse_ResponseTrailers{
					ResponseTrailers: &extproc.TrailersResponse{},
				},
			}
		}

		if err := stream.Send(resp); err != nil {
			log.Printf("send error: %v", err)
			return err
		}
	}
}

func dropUnknownTransaction(stream extproc.ExternalProcessor_ProcessServer) error {
	resp := &extproc.ProcessingResponse{
		Response: &extproc.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &extproc.ImmediateResponse{
				Status: &envoy_type.HttpStatus{Code: envoy_type.StatusCode_Forbidden},
				Body:   []byte("Unknown transaction"),
			},
		},
	}
	stream.Send(resp)
	return nil
}

func getHeaderValue(headers *envoy_core.HeaderMap, key string) string {
	if headers == nil {
		return ""
	}

	for _, h := range headers.Headers {
		if strings.ToLower(h.Key) == key {
			if h.Value != "" {
				return h.Value
			}

			// 2. If empty, convert the RawValue bytes to string
			if len(h.RawValue) > 0 {
				return string(h.RawValue)
			}
		}
	}
	return ""
}
