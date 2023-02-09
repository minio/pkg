package log

import (
	"strings"
	"time"

	"github.com/minio/madmin-go/v2"
)

// ObjectVersion object version key/versionId
type ObjectVersion struct {
	ObjectName string `json:"objectName"`
	VersionID  string `json:"versionId,omitempty"`
}

// Args - defines the arguments for the API.
type Args struct {
	Bucket    string            `json:"bucket,omitempty"`
	Object    string            `json:"object,omitempty"`
	VersionID string            `json:"versionId,omitempty"`
	Objects   []ObjectVersion   `json:"objects,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// Trace - defines the trace.
type Trace struct {
	Message   string                 `json:"message,omitempty"`
	Source    []string               `json:"source,omitempty"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

// API - defines the api type and its args.
type API struct {
	Name string `json:"name,omitempty"`
	Args *Args  `json:"args,omitempty"`
}

// Entry - defines fields and values of each log entry.
type Entry struct {
	DeploymentID string         `json:"deploymentid,omitempty"`
	Level        string         `json:"level"`
	LogKind      madmin.LogKind `json:"errKind"`
	Time         time.Time      `json:"time"`
	API          *API           `json:"api,omitempty"`
	RemoteHost   string         `json:"remotehost,omitempty"`
	Host         string         `json:"host,omitempty"`
	RequestID    string         `json:"requestID,omitempty"`
	UserAgent    string         `json:"userAgent,omitempty"`
	Message      string         `json:"message,omitempty"`
	Trace        *Trace         `json:"error,omitempty"`
}

// Info holds console log messages
type Info struct {
	Entry
	ConsoleMsg string
	NodeName   string `json:"node"`
	Err        error  `json:"-"`
}

// Mask returns the mask based on the error level.
func (l Info) Mask() uint64 {
	return l.LogKind.LogMask().Mask()
}

// SendLog returns true if log pertains to node specified in args.
func (l Info) SendLog(node string, logKind madmin.LogMask) bool {
	if logKind.Contains(l.LogKind.LogMask()) {
		return node == "" || strings.EqualFold(node, l.NodeName) && !l.Time.IsZero()
	}
	return false
}
