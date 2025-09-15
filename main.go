package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/rikatz/envoy-authz-coraza/pkg/waf"
	"google.golang.org/grpc"
)

func main() {
	port := flag.Int("port", 9001, "gRPC port")
	directivesFile := flag.String("directives", "./default.conf", "WAF directive files")
	flag.Parse()

	wafInstance, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithErrorCallback(logError).
		WithDirectivesFromFile(*directivesFile))
	if err != nil {
		log.Fatalf("error loading coraza: %s", err)
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen to %d: %v", *port, err)
	}

	gs := grpc.NewServer()

	envoy_service_auth_v3.RegisterAuthorizationServer(gs, waf.New(wafInstance))

	log.Printf("starting gRPC server on: %d\n", *port)

	gs.Serve(lis)
}

func logError(error types.MatchedRule) {
	msg := error.ErrorLog()
	log.Printf("[logError][%s] %s\n", error.Rule().Severity(), msg)
}
