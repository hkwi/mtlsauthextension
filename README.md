# mTLS Auth Collector Extension

This project provides the `mtlsauthextension` for the OpenTelemetry Collector, enabling extraction of peer TLS information from incoming GRPC and HTTP requests.

## Features
- Extracts peer TLS certificate information (subject, issuer, not_before, not_after) as strings
- Supports both GRPC and HTTP servers
- Provides extracted data as `AuthData` in the request context for downstream components
- Operates with an empty or minimal configuration file

## Usage
1. Add `mtlsauthextension` to your OpenTelemetry Collector configuration.
2. Configure the extension (the config file may be empty or minimal).
3. Start the collector. The extension will extract and provide peer TLS info for each incoming request.

### Example Configuration
```yaml
extensions:
  mtlsauth:
    require_cert: true # default

service:
  extensions:
    - mtlsauth

receivers:
  otlp:
    protocols:
      grpc:
        auth:
          authenticator: mtlsauth
      http:
        auth:
          authenticator: mtlsauth
```

## AuthData Structure
The extracted TLS information is provided as an `AuthData` object with the following fields:
- `subject`: Certificate subject (string)
- `issuer`: Certificate issuer (string)
- `not_before`: Certificate notBefore date/time (string)
- `not_after`: Certificate notAfter date/time (string)

