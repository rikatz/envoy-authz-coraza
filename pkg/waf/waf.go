package waf

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/corazawaf/coraza/v3"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/genproto/googleapis/rpc/status"
)

type server struct {
	waf coraza.WAF
}

var _ envoy_service_auth_v3.AuthorizationServer = &server{}

// New creates a new authorization server.
func New(wafInstance coraza.WAF) envoy_service_auth_v3.AuthorizationServer {
	return &server{wafInstance}
}

// Check implements authorization's Check interface which performs authorization check based on the
// attributes associated with the incoming request.
func (s *server) Check(
	ctx context.Context,
	req *envoy_service_auth_v3.CheckRequest) (*envoy_service_auth_v3.CheckResponse, error) {

	log.Println("received request")

	tx := s.waf.NewTransactionWithID(req.Attributes.Request.Http.Id)
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

	// TODO: Can be a socket, etc
	// TODO2: Convert int to uint properly (avoid leaks)
	client := req.Attributes.Source.Address.GetSocketAddress().GetAddress()
	cPort := req.Attributes.Source.Address.GetSocketAddress().GetPortValue()
	server := req.Attributes.Destination.Address.GetSocketAddress().GetAddress()
	sPort := req.Attributes.Destination.Address.GetSocketAddress().GetPortValue()

	log.Printf("Got connection from %s:%d // %s:%d", client, cPort, server, sPort)
	tx.ProcessConnection(client, int(cPort), server, int(sPort))

	reqHTTP := req.Attributes.Request.Http

	tx.ProcessURI(reqHTTP.Path, reqHTTP.Method, reqHTTP.Protocol)
	tx.SetServerName(reqHTTP.GetHost())

	for k, v := range reqHTTP.Headers {
		// skip internal envoy headers
		if strings.HasPrefix(k, ":") {
			continue
		}
		tx.AddRequestHeader(k, v)
	}

	// TODO: internal parsing errors can occur, we need to fetch those via log callback from coraza
	if it := tx.ProcessRequestHeaders(); it != nil {
		log.Printf("interruption occured: %+v", it)
		return &envoy_service_auth_v3.CheckResponse{
			Status: &status.Status{
				Code:    int32(code.Code_PERMISSION_DENIED),
				Message: fmt.Sprintf("denied by %+v", it),
			},
		}, nil
	}

	return &envoy_service_auth_v3.CheckResponse{
		Status: &status.Status{
			Code: int32(code.Code_OK),
		},
	}, nil

}
