package reporter

import (
	"bytes"
	"text/template"

	"clair_reporter/clair"
)

func fillTemplate(failure clair.JiraTicket, format string) (string, error) {
	tmpl, err := template.New("").Funcs(map[string]interface{}{
		// "config": config,
		// TODO: Use ParseFiles https://golang.org/pkg/text/template/#Template.ParseFiles
	}).Parse(format)
	if err != nil {
		return "", err
	}

	buf := bytes.NewBuffer([]byte{})

	err = tmpl.Execute(buf, map[string]interface{}{
		"nl":      "\n",
		"failure": failure,
	})

	return string(buf.Bytes()), err
}
