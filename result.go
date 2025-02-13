package main

// URLScanResult is the top‐level structure.
type URLScanResult struct {
	Data      Data      `json:"data"`
	Lists     Lists     `json:"lists"`
	Meta      Meta      `json:"meta"`
	Page      Page      `json:"page"`
	Scanner   Scanner   `json:"scanner"`
	Stats     Stats     `json:"stats"`
	Submitter Submitter `json:"submitter"`
	Task      Task      `json:"task"`
	Verdicts  Verdicts  `json:"verdicts"`
}

// ---------------------
// Data section
// ---------------------

type Data struct {
	Requests []RequestEntry `json:"requests"`
	Cookies  []Cookie       `json:"cookies"`
	Console  []ConsoleEntry `json:"console"`
	Links    []interface{}  `json:"links"`
	Timing   Timing         `json:"timing"`
	Globals  []Global       `json:"globals"`
}

type RequestEntry struct {
	Request       RequestDetail  `json:"request"`
	Response      ResponseDetail `json:"response"`
	InitiatorInfo *InitiatorInfo `json:"initiatorInfo,omitempty"`
}

type RequestDetail struct {
	RequestId            string       `json:"requestId"`
	LoaderId             string       `json:"loaderId"`
	DocumentURL          string       `json:"documentURL"`
	Request              RequestInner `json:"request"`
	Timestamp            float64      `json:"timestamp"`
	WallTime             float64      `json:"wallTime"`
	Initiator            Initiator    `json:"initiator"`
	RedirectHasExtraInfo bool         `json:"redirectHasExtraInfo"`
	Type                 string       `json:"type"`
	FrameId              string       `json:"frameId"`
	HasUserGesture       bool         `json:"hasUserGesture"`
	PrimaryRequest       *bool        `json:"primaryRequest,omitempty"`
	// primaryRequest appears only on some requests
}

type RequestInner struct {
	URL              string            `json:"url"`
	Method           string            `json:"method"`
	Headers          map[string]string `json:"headers"`
	MixedContentType string            `json:"mixedContentType"`
	InitialPriority  string            `json:"initialPriority"`
	ReferrerPolicy   string            `json:"referrerPolicy"`
	IsSameSite       bool              `json:"isSameSite"`
}

type Initiator struct {
	Type         string `json:"type"`
	URL          string `json:"url,omitempty"`
	LineNumber   *int   `json:"lineNumber,omitempty"`
	ColumnNumber *int   `json:"columnNumber,omitempty"`
}

type ResponseDetail struct {
	EncodedDataLength int           `json:"encodedDataLength"`
	DataLength        int           `json:"dataLength"`
	RequestId         string        `json:"requestId"`
	Type              string        `json:"type"`
	Response          ResponseInner `json:"response"`
	HasExtraInfo      bool          `json:"hasExtraInfo"`
	Hash              string        `json:"hash"`
	Size              int           `json:"size"`
	Asn               AsnDetail     `json:"asn"`
}

type ResponseInner struct {
	URL                    string            `json:"url"`
	Status                 int               `json:"status"`
	StatusText             string            `json:"statusText"`
	Headers                map[string]string `json:"headers"`
	MimeType               string            `json:"mimeType"`
	Charset                string            `json:"charset"`
	RemoteIPAddress        string            `json:"remoteIPAddress"`
	RemotePort             int               `json:"remotePort"`
	EncodedDataLength      int               `json:"encodedDataLength"`
	Timing                 TimingDetail      `json:"timing"`
	ResponseTime           float64           `json:"responseTime"`
	Protocol               string            `json:"protocol"`
	AlternateProtocolUsage string            `json:"alternateProtocolUsage"`
	SecurityState          string            `json:"securityState"`
	SecurityDetails        SecurityDetails   `json:"securityDetails"`
	SecurityHeaders        []SecurityHeader  `json:"securityHeaders"`
}

type TimingDetail struct {
	RequestTime              float64 `json:"requestTime"`
	ProxyStart               float64 `json:"proxyStart"`
	ProxyEnd                 float64 `json:"proxyEnd"`
	DnsStart                 float64 `json:"dnsStart"`
	DnsEnd                   float64 `json:"dnsEnd"`
	ConnectStart             float64 `json:"connectStart"`
	ConnectEnd               float64 `json:"connectEnd"`
	SslStart                 float64 `json:"sslStart"`
	SslEnd                   float64 `json:"sslEnd"`
	WorkerStart              float64 `json:"workerStart"`
	WorkerReady              float64 `json:"workerReady"`
	WorkerFetchStart         float64 `json:"workerFetchStart"`
	WorkerRespondWithSettled float64 `json:"workerRespondWithSettled"`
	SendStart                float64 `json:"sendStart"`
	SendEnd                  float64 `json:"sendEnd"`
	PushStart                float64 `json:"pushStart"`
	PushEnd                  float64 `json:"pushEnd"`
	ReceiveHeadersStart      float64 `json:"receiveHeadersStart"`
	ReceiveHeadersEnd        float64 `json:"receiveHeadersEnd"`
}

type SecurityDetails struct {
	Protocol                          string   `json:"protocol"`
	KeyExchange                       string   `json:"keyExchange"`
	KeyExchangeGroup                  string   `json:"keyExchangeGroup"`
	Cipher                            string   `json:"cipher"`
	CertificateId                     int      `json:"certificateId"`
	SubjectName                       string   `json:"subjectName"`
	SanList                           []string `json:"sanList"`
	Issuer                            string   `json:"issuer"`
	ValidFrom                         int64    `json:"validFrom"`
	ValidTo                           int64    `json:"validTo"`
	SignedCertificateTimestampList    []SCT    `json:"signedCertificateTimestampList"`
	CertificateTransparencyCompliance string   `json:"certificateTransparencyCompliance"`
	ServerSignatureAlgorithm          int      `json:"serverSignatureAlgorithm"`
	EncryptedClientHello              bool     `json:"encryptedClientHello"`
}

type SCT struct {
	Status             string `json:"status"`
	Origin             string `json:"origin"`
	LogDescription     string `json:"logDescription"`
	LogId              string `json:"logId"`
	Timestamp          int64  `json:"timestamp"`
	HashAlgorithm      string `json:"hashAlgorithm"`
	SignatureAlgorithm string `json:"signatureAlgorithm"`
	SignatureData      string `json:"signatureData"`
}

type SecurityHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type AsnDetail struct {
	IP          string `json:"ip"`
	Asn         string `json:"asn"`
	Country     string `json:"country"`
	Description string `json:"description"`
	Name        string `json:"name"`
	Route       string `json:"route"`
}

type InitiatorInfo struct {
	URL  string `json:"url"`
	Host string `json:"host"`
	Type string `json:"type"`
}

// ---------------------
// Other parts of Data
// ---------------------

type Cookie struct {
	Name         string  `json:"name"`
	Value        string  `json:"value"`
	Domain       string  `json:"domain"`
	Path         string  `json:"path"`
	Expires      float64 `json:"expires"`
	Size         int     `json:"size"`
	HttpOnly     bool    `json:"httpOnly"`
	Secure       bool    `json:"secure"`
	Session      bool    `json:"session"`
	Priority     string  `json:"priority"`
	SameParty    bool    `json:"sameParty"`
	SourceScheme string  `json:"sourceScheme"`
	SourcePort   int     `json:"sourcePort"`
}

type ConsoleEntry struct {
	Message ConsoleMessage `json:"message"`
}

type ConsoleMessage struct {
	Source    string  `json:"source"`
	Level     string  `json:"level"`
	Text      string  `json:"text"`
	Timestamp float64 `json:"timestamp"`
	URL       string  `json:"url"`
}

type Timing struct {
	BeginNavigation      string `json:"beginNavigation"`
	FrameStartedLoading  string `json:"frameStartedLoading"`
	FrameNavigated       string `json:"frameNavigated"`
	DomContentEventFired string `json:"domContentEventFired"`
	FrameStoppedLoading  string `json:"frameStoppedLoading"`
}

type Global struct {
	Prop string `json:"prop"`
	Type string `json:"type"`
}

// ---------------------
// Lists section
// ---------------------

type Lists struct {
	Ips          []string      `json:"ips"`
	Countries    []string      `json:"countries"`
	Asns         []string      `json:"asns"`
	Domains      []string      `json:"domains"`
	Servers      []string      `json:"servers"`
	Urls         []string      `json:"urls"`
	LinkDomains  []string      `json:"linkDomains"`
	Certificates []Certificate `json:"certificates"`
	Hashes       []string      `json:"hashes"`
}

type Certificate struct {
	SubjectName string `json:"subjectName"`
	Issuer      string `json:"issuer"`
	ValidFrom   int64  `json:"validFrom"`
	ValidTo     int64  `json:"validTo"`
}

// ---------------------
// Meta section
// ---------------------

type Meta struct {
	Processors Processors `json:"processors"`
}

type Processors struct {
	Umbrella UmbrellaProcessor `json:"umbrella"`
	Geoip    GeoipProcessor    `json:"geoip"`
	Asn      AsnProcessor      `json:"asn"`
	Rdns     RdnsProcessor     `json:"rdns"`
	Wappa    WappaProcessor    `json:"wappa"`
}

type UmbrellaProcessor struct {
	Data []struct {
		Hostname string `json:"hostname"`
		Rank     int    `json:"rank"`
	} `json:"data"`
}

type GeoipProcessor struct {
	Data []struct {
		Ip    string     `json:"ip"`
		Geoip *GeoipInfo `json:"geoip,omitempty"`
	} `json:"data"`
}

type GeoipInfo struct {
	Country     string    `json:"country"`
	Region      string    `json:"region"`
	Timezone    string    `json:"timezone"`
	City        string    `json:"city"`
	Ll          []float64 `json:"ll"`
	CountryName string    `json:"country_name"`
	Metro       int       `json:"metro"`
}

type AsnProcessor struct {
	Data []struct {
		Ip          string `json:"ip"`
		Asn         string `json:"asn"`
		Country     string `json:"country"`
		Description string `json:"description"`
		Name        string `json:"name"`
		Route       string `json:"route"`
	} `json:"data"`
}

type RdnsProcessor struct {
	Data []struct {
		Ip  string `json:"ip"`
		Ptr string `json:"ptr"`
	} `json:"data"`
}

type WappaProcessor struct {
	Data []struct {
		Confidence []struct {
			Confidence int    `json:"confidence"`
			Pattern    string `json:"pattern"`
		} `json:"confidence"`
		ConfidenceTotal int    `json:"confidenceTotal"`
		App             string `json:"app"`
		Icon            string `json:"icon"`
		Website         string `json:"website"`
		Categories      []struct {
			Name     string `json:"name"`
			Priority int    `json:"priority"`
		} `json:"categories"`
	} `json:"data"`
}

// ---------------------
// Page section
// ---------------------

type Page struct {
	Asn          string `json:"asn"`
	Asnname      string `json:"asnname"`
	Domain       string `json:"domain"`
	Ip           string `json:"ip"`
	Server       string `json:"server"`
	Url          string `json:"url"`
	MimeType     string `json:"mimeType"`
	Title        string `json:"title"`
	TlsValidDays int    `json:"tlsValidDays"`
	TlsAgeDays   int    `json:"tlsAgeDays"`
	TlsValidFrom string `json:"tlsValidFrom"`
	ApexDomain   string `json:"apexDomain"`
	TlsIssuer    string `json:"tlsIssuer"`
	Status       string `json:"status"`
}

// ---------------------
// Scanner section
// ---------------------

type Scanner struct {
	Country string `json:"country"`
}

// ---------------------
// Stats section
// ---------------------

type Stats struct {
	IPv6Percentage   int             `json:"IPv6Percentage"`
	AdBlocked        int             `json:"adBlocked"`
	DomainStats      []DomainStat    `json:"domainStats"`
	IpStats          []IpStat        `json:"ipStats"`
	Malicious        int             `json:"malicious"`
	ProtocolStats    []ProtocolStat  `json:"protocolStats"`
	RegDomainStats   []RegDomainStat `json:"regDomainStats"`
	ResourceStats    []ResourceStat  `json:"resourceStats"`
	SecurePercentage int             `json:"securePercentage"`
	SecureRequests   int             `json:"secureRequests"`
	ServerStats      []ServerStat    `json:"serverStats"`
	TlsStats         []TlsStat       `json:"tlsStats"`
	TotalLinks       int             `json:"totalLinks"`
	UniqCountries    int             `json:"uniqCountries"`
}

type DomainStat struct {
	Count       int      `json:"count"`
	Ips         []string `json:"ips"`
	Domain      string   `json:"domain"`
	Size        int      `json:"size"`
	EncodedSize int      `json:"encodedSize"`
	Countries   []string `json:"countries"`
	Index       int      `json:"index"`
	Initiators  []string `json:"initiators"`
	Redirects   int      `json:"redirects"`
}

type IpStat struct {
	Requests    int                    `json:"requests"`
	Domains     []string               `json:"domains"`
	Ip          string                 `json:"ip"`
	Asn         AsnDetail              `json:"asn"`
	Dns         map[string]interface{} `json:"dns"`
	Size        int                    `json:"size"`
	EncodedSize int                    `json:"encodedSize"`
	Countries   []string               `json:"countries"`
	Index       int                    `json:"index"`
	Ipv6        bool                   `json:"ipv6"`
	Redirects   int                    `json:"redirects"`
	Count       interface{}            `json:"count"`
	Rdns        *RdnsRecord            `json:"rdns,omitempty"`
}

type RdnsRecord struct {
	Ip  string `json:"ip"`
	Ptr string `json:"ptr"`
}

type ProtocolStat struct {
	Count         int                    `json:"count"`
	Size          int                    `json:"size"`
	EncodedSize   int                    `json:"encodedSize"`
	Ips           []string               `json:"ips"`
	Countries     []string               `json:"countries"`
	SecurityState map[string]interface{} `json:"securityState"`
	Protocol      string                 `json:"protocol"`
}

type RegDomainStat struct {
	Count       int         `json:"count"`
	Ips         []string    `json:"ips"`
	RegDomain   string      `json:"regDomain"`
	Size        int         `json:"size"`
	EncodedSize int         `json:"encodedSize"`
	Countries   []string    `json:"countries"`
	Index       int         `json:"index"`
	SubDomains  []SubDomain `json:"subDomains"`
	Redirects   int         `json:"redirects"`
}

type SubDomain struct {
	Domain  string `json:"domain"`
	Country string `json:"country"`
}

type ResourceStat struct {
	Count       int      `json:"count"`
	Size        int      `json:"size"`
	EncodedSize int      `json:"encodedSize"`
	Latency     int      `json:"latency"`
	Countries   []string `json:"countries"`
	Ips         []string `json:"ips"`
	Type        string   `json:"type"`
	Compression string   `json:"compression"`
	Percentage  int      `json:"percentage"`
}

type ServerStat struct {
	Count       int      `json:"count"`
	Size        int      `json:"size"`
	EncodedSize int      `json:"encodedSize"`
	Ips         []string `json:"ips"`
	Countries   []string `json:"countries"`
	Server      string   `json:"server"`
}

type TlsStat struct {
	Count         int            `json:"count"`
	Size          int            `json:"size"`
	EncodedSize   int            `json:"encodedSize"`
	Ips           []string       `json:"ips"`
	Countries     []string       `json:"countries"`
	Protocols     map[string]int `json:"protocols"`
	SecurityState string         `json:"securityState"`
}

// ---------------------
// Submitter section
// ---------------------

type Submitter struct {
	Country string `json:"country"`
}

// ---------------------
// Task section
// ---------------------

type Task struct {
	ApexDomain    string        `json:"apexDomain"`
	Domain        string        `json:"domain"`
	Method        string        `json:"method"`
	Source        string        `json:"source"`
	Tags          []interface{} `json:"tags"`
	Time          string        `json:"time"`
	Url           string        `json:"url"`
	Uuid          string        `json:"uuid"`
	Visibility    string        `json:"visibility"`
	ReportURL     string        `json:"reportURL"`
	ScreenshotURL string        `json:"screenshotURL"`
	DomURL        string        `json:"domURL"`
}

// ---------------------
// Verdicts section
// ---------------------

type Verdicts struct {
	Overall   Verdict        `json:"overall"`
	Urlscan   Verdict        `json:"urlscan"`
	Engines   EnginesVerdict `json:"engines"`
	Community Verdict        `json:"community"`
}

type Verdict struct {
	Score       int           `json:"score"`
	Categories  []interface{} `json:"categories"`
	Brands      []interface{} `json:"brands"`
	Tags        []interface{} `json:"tags"`
	Malicious   bool          `json:"malicious"`
	HasVerdicts bool          `json:"hasVerdicts"`
}

type EnginesVerdict struct {
	Score             int           `json:"score"`
	Categories        []interface{} `json:"categories"`
	EnginesTotal      int           `json:"enginesTotal"`
	MaliciousTotal    int           `json:"maliciousTotal"`
	BenignTotal       int           `json:"benignTotal"`
	MaliciousVerdicts []interface{} `json:"maliciousVerdicts"`
	BenignVerdicts    []interface{} `json:"benignVerdicts"`
	Malicious         bool          `json:"malicious"`
}

// =============================================================================
// Methods to generate reports
// =============================================================================

// GenerateReport produces a detailed information security report.
func (r *URLScanResult) GenerateReport() map[string]any {
	report := make(map[string]any)

	// Basic page and TLS info
	report["domain"] = r.Page.Domain
	report["ip"] = r.Page.Ip
	report["server"] = r.Page.Server
	report["title"] = r.Page.Title
	report["tls"] = map[string]any{
		"valid_days": r.Page.TlsValidDays,
		"age_days":   r.Page.TlsAgeDays,
		"issuer":     r.Page.TlsIssuer,
	}

	report["asn"] = r.Page.Asn

	// Requests summary
	totalRequests := len(r.Data.Requests)
	report["total_requests"] = totalRequests
	report["secure_requests"] = r.Stats.SecureRequests
	if totalRequests > 0 {
		report["secure_percentage"] = float64(r.Stats.SecureRequests) / float64(totalRequests) * 100
	}

	// Domain statistics (from stats)
	domainSummaries := []map[string]any{}
	for _, ds := range r.Stats.DomainStats {
		domainSummaries = append(domainSummaries, map[string]any{
			"domain":       ds.Domain,
			"requestCount": ds.Count,
			"size":         ds.Size,
			"encodedSize":  ds.EncodedSize,
			"ips":          ds.Ips,
		})
	}
	report["domain_stats"] = domainSummaries

	// TLS statistics (if available)
	if len(r.Stats.TlsStats) > 0 {
		tlsStat := r.Stats.TlsStats[0]
		report["tls_protocols"] = tlsStat.Protocols
		report["tls_security_state"] = tlsStat.SecurityState
	}

	// Certificate details from the Lists section
	certSummaries := []map[string]any{}
	for _, cert := range r.Lists.Certificates {
		certSummaries = append(certSummaries, map[string]any{
			"subject":    cert.SubjectName,
			"issuer":     cert.Issuer,
			"valid_from": cert.ValidFrom,
			"valid_to":   cert.ValidTo,
		})
	}
	report["certificates"] = certSummaries

	// Collect security details from each response (if available)
	secDetails := []map[string]any{}
	for _, reqEntry := range r.Data.Requests {
		sd := reqEntry.Response.Response.SecurityDetails
		if sd.Protocol != "" {
			secDetails = append(secDetails, map[string]any{
				"url":      reqEntry.Response.Response.URL,
				"protocol": sd.Protocol,
				"cipher":   sd.Cipher,
				"subject":  sd.SubjectName,
				"issuer":   sd.Issuer,
			})
		}
	}
	report["security_details"] = secDetails

	// Verdicts summary
	report["verdicts"] = map[string]any{
		"overall":   r.Verdicts.Overall,
		"urlscan":   r.Verdicts.Urlscan,
		"engines":   r.Verdicts.Engines,
		"community": r.Verdicts.Community,
	}

	return report
}
