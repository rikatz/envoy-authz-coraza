# Envoy Coraza based WAF Filter

**This is a PoC, do not use in production!**

This project contains a simple implementation of [Envoy Authorization Filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter#config-http-filters-ext-authz)
that uses [Coraza WAF](https://coraza.io/) to execute request filtering and Authorization.

## Quick start:
Having `docker-compose` installed, simply run `docker compose up --build`.

After the service is available, on a different terminal you can test the rules using:

```
$ curl --fail localhost:8000/service?id=0
curl: (22) The requested URL returned error: 403

$ curl --data "lalalala" --resolve xpto:8000:127.0.0.1 http://xpto:8000/service?id=1
curl: (22) The requested URL returned error: 403

$ curl --fail localhost:8000/service?id=1
{
 "path": "/service?id=1",
 "host": "localhost:8000",
 ...
}
```

This happens because the current used [WAF Rules](./default.conf) filter requests that 
contains the query arg `id`, blocking any request where `id=0` and also any request that
contains the string "lalalala" in its body

## tl;dr architecture

The service is a gRPC implementation of the ext_authz protocol, that instantiates a 
new WAF parsing the rules file (currently [./default.conf](default.conf)) and listens 
on port 9001.

Envoy then can establish a filter and an upstream to request for the "decision" of this request. Please
check the file [config/envoy.yaml](config/envoy.yaml) for a better example.

```yaml
http_filters:
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    grpc_service:
      envoy_grpc:
        cluster_name: ext_authz-grpc-service
      timeout: 0.250s
```

## Why did you...

* Not used a WASM filter? 

WASM has some limitations, and while I am a huge fan of using it, doing things like "reading from filesystem" is not supported (at least wasn't AFAIK)

* Not created an Envoy Go plugin (or used the [existing](https://github.com/united-security-providers/coraza-envoy-go-filter))? 

Mostly because the Envoy Go plugin ecossystem is still experimental, and relies on CGO. The CGO need can become a problem to 
compile future Envoy versions and keep compatibility with this module. I wanted to make it as much generic as possible. This doesn't
mean the existing project or the Envoy Go plugin is not good, just means that I wanted to try something simpler!

* Created a gRPC extension?

Mostly because the API for Envoy ext_auth is well defined, and the protobufs are already available. I could create a 
HTTP service instead, but that would mean I would had to implement the full HTTP service and parsing, while 
with gRPC I can simply care on implementing the right method, getting the information and
doing the WAFy things :) 

## TODO
* Implement a way to download OWASP CRS Rules
* Implement body parsing/filtering
* Implement response parsing
* Do some benchmark
