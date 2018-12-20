// Lifted from https://github.com/optiopay/klar/blob/master/clair/clair.go
package clair

type KlarReport struct {
	Repo            string                `json:"repo"`
	Vulnerabilities map[string][]*Feature `json:"vulnerabilities"`
}

type Feature struct {
	ImageTag string `json:"image_tag"`
	Version  string `json:"version"`
	Severity string `json:"severity"`
	FixedBy  string `json:"fixed_by"`
	Link     string `json:"link"`
}

type JiraTicket struct {
	Repo        string
	Package     string
	Description string
	DevTeam     string
}
