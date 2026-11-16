Test-only TLS fixtures (throwaway CAs; CA keys discarded).
- ca.pem -> backend.pem/backend.key (DNS backend.test, URI spiffe://test/backend)
- client-ca.pem -> client.pem/client.key (CN test-client, clientAuth)
