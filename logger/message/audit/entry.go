package audit

import "time"

// ObjectVersion object version key/versionId
type ObjectVersion struct {
	ObjectName string `json:"objectName"`
	VersionID  string `json:"versionId,omitempty"`
}

// Entry - audit entry logs.
type Entry struct {
	Version      string    `json:"version"`
	DeploymentID string    `json:"deploymentid,omitempty"`
	Time         time.Time `json:"time"`
	Event        string    `json:"event"`
	// deprecated replaced by 'Event', kept here for some
	// time for backward compatibility with k8s Operator.
	Trigger string `json:"trigger"`
	API     struct {
		Name            string          `json:"name,omitempty"`
		Bucket          string          `json:"bucket,omitempty"`
		Object          string          `json:"object,omitempty"`
		Objects         []ObjectVersion `json:"objects,omitempty"`
		Status          string          `json:"status,omitempty"`
		StatusCode      int             `json:"statusCode,omitempty"`
		InputBytes      int64           `json:"rx"`
		OutputBytes     int64           `json:"tx"`
		HeaderBytes     int64           `json:"txHeaders,omitempty"`
		TimeToFirstByte string          `json:"timeToFirstByte,omitempty"`
		TimeToResponse  string          `json:"timeToResponse,omitempty"`
	} `json:"api"`
	RemoteHost string                 `json:"remotehost,omitempty"`
	RequestID  string                 `json:"requestID,omitempty"`
	UserAgent  string                 `json:"userAgent,omitempty"`
	ReqClaims  map[string]interface{} `json:"requestClaims,omitempty"`
	ReqQuery   map[string]string      `json:"requestQuery,omitempty"`
	ReqHeader  map[string]string      `json:"requestHeader,omitempty"`
	RespHeader map[string]string      `json:"responseHeader,omitempty"`
	Tags       map[string]interface{} `json:"tags,omitempty"`

	AccessKey  string `json:"accessKey,omitempty"`
	ParentUser string `json:"parentUser,omitempty"`

	Error string `json:"error,omitempty"`
}
