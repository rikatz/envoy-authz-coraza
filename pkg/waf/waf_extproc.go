package waf

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
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
	id           string
	tx           types.Transaction
	requestBody  bytes.Buffer
	responseBody bytes.Buffer
	//req *extproc.ProcessingRequest_RequestHeaders
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
	var resp = &extproc.ProcessingResponse{}
	var tx *requestTransaction

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

		switch v := req.Request.(type) {
		// First case / step is the request Headers. We can drop here already in case
		// something matches an early rule for IP, port, etc
		case *extproc.ProcessingRequest_RequestHeaders:
			tx, err = s.newTransaction(v)
			if err != nil {
				return dropTransaction(stream, err)
			}
			transactionID = tx.tx.ID()

			// First step can also add the transaction logging and transaction closing
			defer func() {
				tx.tx.ProcessLogging()
				if err := tx.tx.Close(); err != nil {
					log.Printf("tx %s failed to close transaction %s", tx.tx.ID(), err)
				}
			}()
			// TODO: RequestHeaders has a EndOfStream bool, is there a case where
			// more than one RequestHeader calls will be made to fill other headers?
			// TODO1 (for safety) - can RequestHeaders be null here? We must verify this pointer
			// (all of the fields that can be nullable)
			if err := tx.processRequestHeaders(req.GetAttributes(), v.RequestHeaders.Headers); err != nil {
				return dropTransaction(stream, err)
			}
			resp = &extproc.ProcessingResponse{
				Response: &extproc.ProcessingResponse_RequestHeaders{
					RequestHeaders: &extproc.HeadersResponse{},
				},
			}

		case *extproc.ProcessingRequest_RequestBody:
			if transactionID == "" || tx == nil {
				return dropUnknownTransaction(stream)
			}

			if err := tx.processRequestBody(v.RequestBody); err != nil {
				return dropTransaction(stream, err)
			}
			resp = &extproc.ProcessingResponse{
				Response: &extproc.ProcessingResponse_RequestBody{
					RequestBody: &extproc.BodyResponse{},
				},
			}

		case *extproc.ProcessingRequest_ResponseHeaders:
			// Transaction ID MUST exist before moving to request body or any other part
			if transactionID == "" || tx == nil {
				return dropUnknownTransaction(stream)
			}

			out := fmt.Sprintf("%s RESPONSE_HEADERS: %v\n", ts, v.ResponseHeaders)
			log.Print(out)

			if err := tx.processResponsetHeaders(req.GetAttributes(), v.ResponseHeaders.Headers); err != nil {
				return dropTransaction(stream, err)
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

			if err := tx.processResponseBody(v.ResponseBody); err != nil {
				return dropResponseBodyTransaction(stream, err)
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
		tx:           tx,
		id:           transactionID,
		requestBody:  bytes.Buffer{},
		responseBody: bytes.Buffer{},
	}, nil
}

// processRequestHeaders is the initial step for the WAF. It receives the initial
// request, extract the headers and the transaction ID, and returns a new
// transaction, the transaction ID and an error if something happens on this state
func (r *requestTransaction) processRequestHeaders(attrs map[string]*structpb.Struct, headers *corev3.HeaderMap) error {
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

	method := getHeaderValue(headers, ":method")
	path := getHeaderValue(headers, ":path")
	httpVersion := getAttribute(attrs, "request.protocol")
	r.tx.ProcessURI(path, method, httpVersion)

	hostPort := getHeaderValue(headers, ":authority")
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return fmt.Errorf("error extracting the host header: %w", err)
	}

	r.tx.SetServerName(host)
	setHeaders(headers, r.tx.AddRequestHeader)

	if it := r.tx.ProcessRequestHeaders(); it != nil {
		return fmt.Errorf("request denied by WAF rule %d", it.RuleID)
	}

	return nil
}

// TODO: This is ugly. processRequest and processResponse are identical, we can simplify
// this logic

// processRequestBody will take the body of a request and check against Coraza rules.
// It will return an error in case any issue is found
func (r *requestTransaction) processRequestBody(body *extproc.HttpBody) error {
	_, err := r.requestBody.Write(body.Body)
	if err != nil {
		return fmt.Errorf("error accumulating request body: %w", err)
	}
	// End Of Stream, we can process
	if body.EndOfStream {
		it, _, err := r.tx.WriteRequestBody(r.requestBody.Bytes())
		if err != nil {
			return fmt.Errorf("error parsing the request body: %w", err)
		}
		if it != nil {
			return fmt.Errorf("request denied by WAF rule and action: %d - %s", it.RuleID, it.Action)
		}

		it, err = r.tx.ProcessRequestBody()
		if err != nil {
			return fmt.Errorf("error processing the request body: %w", err)
		}
		if it != nil {
			return fmt.Errorf("request denied by WAF rule and action: %d - %s", it.RuleID, it.Action)
		}
	}
	return nil
}

// processRequestHeaders is the initial step for the WAF. It receives the initial
// request, extract the headers and the transaction ID, and returns a new
// transaction, the transaction ID and an error if something happens on this state
func (r *requestTransaction) processResponsetHeaders(attrs map[string]*structpb.Struct, headers *corev3.HeaderMap) error {
	responseCode, err := strconv.Atoi(getHeaderValue(headers, ":status"))
	if err != nil {
		return fmt.Errorf("error decoding return code: %w", err)
	}
	// Note: It is not clear if when processing ResponseHeaders coraza cares about the
	// response of upstream, or if the requested protocol vs negotiated protocol are different.
	// this may need to be clarified
	httpVersion := getAttribute(attrs, "request.protocol")
	setHeaders(headers, r.tx.AddResponseHeader)

	if it := r.tx.ProcessResponseHeaders(responseCode, httpVersion); it != nil {
		return fmt.Errorf("request denied by WAF rule %d", it.RuleID)
	}

	return nil
}

// processRequesprocessResponseBodytBody will take the body of a response and check against Coraza rules.
// It will return an error in case any issue is found
func (r *requestTransaction) processResponseBody(body *extproc.HttpBody) error {
	_, err := r.responseBody.Write(body.Body)
	if err != nil {
		return fmt.Errorf("error accumulating response body: %w", err)
	}
	// End Of Stream, we can process
	if body.EndOfStream {
		it, _, err := r.tx.WriteResponseBody(r.responseBody.Bytes())
		if err != nil {
			return fmt.Errorf("error parsing the response body: %w", err)
		}
		if it != nil {
			return fmt.Errorf("request denied by WAF rule and action: %d - %s", it.RuleID, it.Action)
		}

		it, err = r.tx.ProcessResponseBody()
		if err != nil {
			return fmt.Errorf("error processing the response body: %w", err)
		}
		if it != nil {
			return fmt.Errorf("request denied by WAF rule and action: %d - %s", it.RuleID, it.Action)
		}
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
				Body:   []byte(fmt.Sprintf("403 Forbidden: Blocked by WAF - %s", err.Error())),
				Headers: &extproc.HeaderMutation{
					SetHeaders: []*corev3.HeaderValueOption{
						{Header: &corev3.HeaderValue{Key: "content-type", Value: "text/plain"}},
					},
				},
			},
		},
	}
	stream.Send(resp)
	return nil
}

func dropResponseBodyTransaction(stream extproc.ExternalProcessor_ProcessServer, err error) error {
	resp := &extproc.ProcessingResponse{}
	resp.Response = &extproc.ProcessingResponse_ResponseBody{
		ResponseBody: &extproc.BodyResponse{
			Response: &extproc.CommonResponse{
				// 1. Scrub the data so it doesn't leak
				BodyMutation: &extproc.BodyMutation{
					Mutation: &extproc.BodyMutation_ClearBody{
						ClearBody: true,
					},
				},
				// 2. Kill the connection immediately after this chunk
				HeaderMutation: &extproc.HeaderMutation{
					SetHeaders: []*corev3.HeaderValueOption{
						// This tells Envoy/Browser to terminate the TCP connection
						{Header: &corev3.HeaderValue{Key: "connection", Value: "close"}},
					},
				},
			},
		},
	}
	stream.Send(resp)
	return nil
}

func setHeaders(headers *corev3.HeaderMap, addHeaderFunc func(key string, value string)) {
	if addHeaderFunc == nil {
		return
	}
	for _, h := range headers.Headers {
		if !strings.HasPrefix(h.Key, ":") {
			value := h.Value
			if value == "" {
				value = string(h.RawValue)
			}
			addHeaderFunc(h.Key, value)
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

			if len(h.RawValue) > 0 {
				return string(h.RawValue)
			}
		}
	}
	return ""
}
