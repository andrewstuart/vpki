module astuart.co/vpki

go 1.12

require (
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.0 // indirect
	github.com/hashicorp/vault/api v1.3.0
	github.com/pierrec/lz4 v2.6.1+incompatible // indirect
	github.com/prometheus/client_golang v1.11.0
	golang.org/x/time v0.0.0-20210723032227-1f47c861a9ac // indirect
)

replace go.etcd.io/etcd/client/pkg/v3 v3.5.0 => go.etcd.io/etcd/client/pkg/v3 v3.0.0-20210928084031-3df272774672
