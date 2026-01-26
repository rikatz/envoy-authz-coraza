package waf

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

type serverExtProc struct {
	waf coraza.WAF
}

type requestTransaction struct {
	id  string
	tx  types.Transaction
	req *extproc.ProcessingRequest_RequestHeaders
}

var _ extproc.ExternalProcessorServer = &serverExtProc{}

// New creates a new ext_proc server.
func NewExtProc(wafInstance coraza.WAF) extproc.ExternalProcessorServer {
	return &serverExtProc{
		waf: wafInstance,
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
			return err
		}

		var resp = &extproc.ProcessingResponse{}

		switch v := req.Request.(type) {
		// First case / step is the request Headers. We can drop here already in case
		// something matches an early rule for IP, port, etc
		case *extproc.ProcessingRequest_RequestHeaders:
			tx, err := s.newTransaction(v)
			if err != nil {
				return dropTransaction(stream, err)
			}
			transactionID = tx.id

			defer func() {
				tx.tx.ProcessLogging()
				if err := tx.tx.Close(); err != nil {
					log.Printf("tx %s failed to close transaction %s", tx.tx.ID(), err)
				}
			}()
			if err := tx.processRequestHeaders(req.GetAttributes()); err != nil {
				return dropTransaction(stream, err)
			}
			resp = &extproc.ProcessingResponse{
				Response: &extproc.ProcessingResponse_RequestHeaders{
					RequestHeaders: &extproc.HeadersResponse{},
				},
			}

		case *extproc.ProcessingRequest_RequestBody:
			// Transaction ID MUST exist before moving to request body or any other part
			if transactionID == "" {
				return dropUnknownTransaction(stream)
			}
			if b := req.GetRequestBody(); b != nil {
				out := fmt.Sprintf("%s REQUEST_BODY (end_of_stream=%v, body_len=%d, body=%s)\n", ts, b.EndOfStream, len(b.GetBody()), string(b.Body))
				log.Print(out)
			}
			resp = &extproc.ProcessingResponse{
				Response: &extproc.ProcessingResponse_RequestBody{
					RequestBody: &extproc.BodyResponse{},
				},
			}

		case *extproc.ProcessingRequest_ResponseHeaders:
			// Transaction ID MUST exist before moving to request body or any other part
			if transactionID == "" {
				return dropUnknownTransaction(stream)
			}
			if rh := req.GetResponseHeaders(); rh != nil {
				out := fmt.Sprintf("%s RESPONSE_HEADERS: %v\n", ts, rh)
				log.Print(out)
			}
			resp = &extproc.ProcessingResponse{
				Response: &extproc.ProcessingResponse_ResponseHeaders{
					ResponseHeaders: &extproc.HeadersResponse{},
				},
			}

		case *extproc.ProcessingRequest_ResponseBody:
			// Transaction ID MUST exist before moving to request body or any other part
			if transactionID == "" {
				return dropUnknownTransaction(stream)
			}
			if rb := req.GetResponseBody(); rb != nil {
				out := fmt.Sprintf("%s RESPONSE_BODY (end_of_stream=%v, body_len=%d, body=%s)\n", ts, rb.EndOfStream, len(rb.GetBody()), string(rb.Body))
				log.Print(out)
			}
			resp = &extproc.ProcessingResponse{
				Response: &extproc.ProcessingResponse_ResponseBody{
					ResponseBody: &extproc.BodyResponse{},
				},
			}
		}

		// CONTINUE processing without modification

		/* 		if req.GetRequestTrailers() != nil {
		   			resp = &extproc.ProcessingResponse{
		   				Response: &extproc.ProcessingResponse_RequestTrailers{
		   					RequestTrailers: &extproc.TrailersResponse{},
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
		*/
		if err := stream.Send(resp); err != nil {
			log.Printf("send error: %v", err)
			return err
		}
	}
}

func (s *serverExtProc) newTransaction(req *extproc.ProcessingRequest_RequestHeaders) (*requestTransaction, error) {
	h := req.RequestHeaders.Headers
	transactionID := getHeaderValue(h, "x-request-id")
	if transactionID == "" {
		return nil, errors.New("unknown transaction")
	}

	tx := s.waf.NewTransactionWithID(transactionID)
	return &requestTransaction{
		req: req,
		tx:  tx,
		id:  transactionID,
	}, nil
}

// processRequestHeaders is the initial step for the WAF. It receives the initial
// request, extract the headers and the transaction ID, and returns a new
// transaction, the transaction ID and an error if something happens on this state
func (r *requestTransaction) processRequestHeaders(attrs map[string]*structpb.Struct) error {

	srcAddrPortRaw := getAttribute(attrs, "source.address")
	srcAddrPort, err := netip.ParseAddrPort(srcAddrPortRaw)
	if err != nil {
		return fmt.Errorf("error parsing source address:port %s: %w", srcAddrPortRaw, err)
	}

	dstAddrPortRaw := getAttribute(attrs, "source.address")
	dstAddrPort, err := netip.ParseAddrPort(dstAddrPortRaw)
	if err != nil {
		return fmt.Errorf("error parsing destination address:port %s: %w", dstAddrPortRaw, err)
	}

	r.tx.ProcessConnection(srcAddrPort.Addr().String(), int(srcAddrPort.Port()), dstAddrPort.Addr().String(), int(dstAddrPort.Port()))

	method := getHeaderValue(r.req.RequestHeaders.Headers, ":method")
	path := getHeaderValue(r.req.RequestHeaders.Headers, ":path")
	httpVersion := getAttribute(attrs, "request.protocol")
	r.tx.ProcessURI(path, method, httpVersion)

	hostPort := getHeaderValue(r.req.RequestHeaders.Headers, ":authority")
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return fmt.Errorf("error extracting the host header: %w", err)
	}

	r.tx.SetServerName(host)
	r.setHeaders()

	if it := r.tx.ProcessRequestHeaders(); it != nil {
		return fmt.Errorf("request denied by WAF rule %d", it.RuleID)
	}

	return nil
}

func dropUnknownTransaction(stream extproc.ExternalProcessor_ProcessServer) error {
	return dropTransaction(stream, errors.New("unknown transaction"))
}

func dropTransaction(stream extproc.ExternalProcessor_ProcessServer, err error) error {
	resp := &extproc.ProcessingResponse{
		Response: &extproc.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &extproc.ImmediateResponse{
				Status: &envoy_type.HttpStatus{Code: envoy_type.StatusCode_Forbidden},
				Body:   []byte(err.Error()),
			},
		},
	}
	stream.Send(resp)
	return nil
}

func (r *requestTransaction) setHeaders() {
	for _, h := range r.req.RequestHeaders.Headers.Headers {
		if !strings.HasPrefix(h.Key, ":") {
			value := h.Value
			if value == "" {
				value = string(h.RawValue)
			}
			r.tx.AddRequestHeader(h.Key, value)
		}
	}
}

func getAttribute(attrs map[string]*structpb.Struct, key string) string {
	log.Printf("ATTRS %+v", attrs)

	if attrs == nil {
		return ""
	}

	extfields, ok := attrs["envoy.filters.http.ext_proc"]
	if !ok {
		return ""
	}

	if v, ok := extfields.Fields[key]; ok {
		return v.GetStringValue()
	}

	return ""

}

func getHeaderValue(headers *corev3.HeaderMap, key string) string {
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
