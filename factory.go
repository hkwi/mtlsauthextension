package mtlsauthextension

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"go.opentelemetry.io/collector/client"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/extension/extensionauth"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type Config struct {
	RequireCert bool `mapstructure:"require_cert"`
}

func NewFactory() extension.Factory {
	return extension.NewFactory(
		component.MustNewType("mtls"),
		func() component.Config {
			return Config{
				RequireCert: true,
			}
		},
		func(
			ctx context.Context,
			setting extension.Settings,
			config component.Config,
		) (extension.Extension, error) {
			return MtlsAuth{
				RequireCert: config.(Config).RequireCert,
			}, nil
		},
		component.StabilityLevelAlpha,
	)
}

type MtlsAuth struct {
	RequireCert bool
}

var (
	// Ensure MtlsAuth implements the extension.Extension and extensionauth.Server interfaces
	_ extension.Extension  = MtlsAuth{}
	_ extensionauth.Server = MtlsAuth{}
)

func (a MtlsAuth) Start(ctx context.Context, host component.Host) error {
	return nil
}

func (a MtlsAuth) Shutdown(ctx context.Context) error {
	return nil
}

var _ client.AuthData = PeerInfo{}

type PeerInfo x509.Certificate

func (p PeerInfo) GetAttribute(name string) any {
	switch name {
	case "tls.client.subject":
		return p.Subject.String()
	case "tls.client.issuer":
		return p.Issuer.String()
	case "tls.client.not_before":
		return p.NotBefore.Format(time.RFC3339)
	case "tls.client.not_after":
		return p.NotAfter.Format(time.RFC3339)
	default:
		return nil
	}
}

func (p PeerInfo) GetAttributeNames() []string {
	return []string{
		"tls.client.subject",
		"tls.client.issuer",
		"tls.client.not_before",
		"tls.client.not_after",
	}
}

func (a MtlsAuth) Authenticate(ctx context.Context, headers map[string][]string) (context.Context, error) {
	if peer, ok := peer.FromContext(ctx); ok {
		if tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo); ok {
			if len(tlsInfo.State.PeerCertificates) > 0 {
				cl := client.FromContext(ctx)
				cl.Auth = (*PeerInfo)(tlsInfo.State.PeerCertificates[0])
				return client.NewContext(ctx, cl), nil
			}
		}
	}
	if a.RequireCert {
		return ctx, fmt.Errorf("no peer certificate. forgot tls.client_ca_file?")
	} else {
		return ctx, nil
	}
}
