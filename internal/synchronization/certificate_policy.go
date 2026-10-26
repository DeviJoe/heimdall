package synchronization

const DefaultNodeCertificateTTLSeconds = 10 * 365 * 86400

type CertificatePolicy struct {
	Version    int64 `json:"version"`
	TTLSeconds int   `json:"ttl_seconds"`
}

func (p CertificatePolicy) Valid() bool {
	return p.Version > 0 && p.TTLSeconds >= 86400 && p.TTLSeconds <= DefaultNodeCertificateTTLSeconds
}
