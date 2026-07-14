package cbom

// This file defines the Go projection of the CycloneDX 1.6 BOM JSON shape that
// cryptoscan emits. Only the subset of the specification cryptoscan populates is
// modelled; every field name matches the CycloneDX 1.6 schema
// (testdata/bom-1.6.schema.json) exactly so the encoded output validates against
// it. Field declaration order is the on-wire order (encoding/json preserves it),
// which — together with sorted slices and no maps — makes the output
// byte-deterministic.

// bom is the top-level CycloneDX document.
type bom struct {
	Schema       string       `json:"$schema,omitempty"`
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber,omitempty"`
	Version      int          `json:"version"`
	Metadata     *metadata    `json:"metadata,omitempty"`
	Components   []component  `json:"components,omitempty"`
	Dependencies []dependency `json:"dependencies,omitempty"`
}

// metadata carries the tool identity, the (optional, injected) timestamp, and
// the estate-level PQC summary as name/value properties.
type metadata struct {
	Timestamp  string     `json:"timestamp,omitempty"`
	Tools      *tools     `json:"tools,omitempty"`
	Properties []property `json:"properties,omitempty"`
}

// tools uses the modern CycloneDX 1.6 object form (tools.components), listing
// cryptoscan itself as the generating tool component.
type tools struct {
	Components []component `json:"components,omitempty"`
}

// component is a single BOM component. For cryptographic assets Type is
// "cryptographic-asset" and CryptoProperties is populated; config/file nodes use
// "data"/"file" and carry their resolved state in Properties.
type component struct {
	Type             string            `json:"type"`
	BOMRef           string            `json:"bom-ref,omitempty"`
	Name             string            `json:"name"`
	Version          string            `json:"version,omitempty"`
	Hashes           []hash            `json:"hashes,omitempty"`
	CryptoProperties *cryptoProperties `json:"cryptoProperties,omitempty"`
	Properties       []property        `json:"properties,omitempty"`
}

// hash is a CycloneDX hash object (alg + hex content).
type hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// property is the CycloneDX lightweight name/value pair.
type property struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

// cryptoProperties is the CycloneDX 1.6 crypto core. AssetType is required and
// selects which of the four *Properties sub-objects is meaningful.
type cryptoProperties struct {
	AssetType                       string                           `json:"assetType"`
	AlgorithmProperties             *algorithmProperties             `json:"algorithmProperties,omitempty"`
	CertificateProperties           *certificateProperties           `json:"certificateProperties,omitempty"`
	RelatedCryptoMaterialProperties *relatedCryptoMaterialProperties `json:"relatedCryptoMaterialProperties,omitempty"`
	ProtocolProperties              *protocolProperties              `json:"protocolProperties,omitempty"`
	OID                             string                           `json:"oid,omitempty"`
}

// algorithmProperties describes a distinct algorithm. NISTQuantumSecurityLevel
// is a pointer so the meaningful value 0 (no post-quantum security) is emitted
// rather than dropped by omitempty.
type algorithmProperties struct {
	Primitive                string   `json:"primitive,omitempty"`
	ParameterSetIdentifier   string   `json:"parameterSetIdentifier,omitempty"`
	Curve                    string   `json:"curve,omitempty"`
	CryptoFunctions          []string `json:"cryptoFunctions,omitempty"`
	NISTQuantumSecurityLevel *int     `json:"nistQuantumSecurityLevel,omitempty"`
}

// certificateProperties describes an X.509 certificate. The DER SHA-256
// fingerprint is carried in component.Hashes (the schema's fingerprint home),
// not here.
type certificateProperties struct {
	SubjectName           string `json:"subjectName,omitempty"`
	IssuerName            string `json:"issuerName,omitempty"`
	NotValidBefore        string `json:"notValidBefore,omitempty"`
	NotValidAfter         string `json:"notValidAfter,omitempty"`
	SignatureAlgorithmRef string `json:"signatureAlgorithmRef,omitempty"`
	SubjectPublicKeyRef   string `json:"subjectPublicKeyRef,omitempty"`
	CertificateFormat     string `json:"certificateFormat,omitempty"`
}

// relatedCryptoMaterialProperties describes key material.
type relatedCryptoMaterialProperties struct {
	Type         string `json:"type,omitempty"`
	ID           string `json:"id,omitempty"`
	AlgorithmRef string `json:"algorithmRef,omitempty"`
	Size         int    `json:"size,omitempty"`
}

// protocolProperties describes a negotiated/observed protocol surface.
type protocolProperties struct {
	Type         string        `json:"type,omitempty"`
	Version      string        `json:"version,omitempty"`
	CipherSuites []cipherSuite `json:"cipherSuites,omitempty"`
}

// cipherSuite is a single TLS cipher-suite entry.
type cipherSuite struct {
	Name        string   `json:"name,omitempty"`
	Identifiers []string `json:"identifiers,omitempty"`
}

// dependency is one node of the CycloneDX dependency graph: Ref depends on
// DependsOn and provides Provides.
type dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
	Provides  []string `json:"provides,omitempty"`
}
