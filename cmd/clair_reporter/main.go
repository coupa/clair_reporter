package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"clair_reporter/clair"
	"clair_reporter/reporter"
)

var f string

func init() {
	flag.StringVar(&f, "file-path", "", "path to the JSON report from klar")
	reporter.RegisterFlags()
}

func main() {
	flag.Parse()
	fmt.Println(f)
	if f == "" {
		log.Fatalf("You must specify a path to the JSON file, pass --file-path <path to json file>")
		os.Exit(1)
	}

	reporters, err := makeReporters()
	if err != nil {
		log.Fatalf("Cannot create requested reporters: %s", err)
	}

	file, err := os.Open(f)
	if err != nil {
		log.Fatalf("Cannot open JSON file %s: %s", f, err)
	}
	defer file.Close()

	reportClairFindings(file, reporters)
}

func reportClairFindings(file *os.File, reporters map[string]reporter.Reporter) {
	klarReport := clair.KlarReport{}
	data, err := ioutil.ReadAll(file)
	if err != nil {
		log.Printf("Cannot read json file: %s", err)
	}

	err = json.Unmarshal(data, &klarReport)
	if err != nil {
		log.Printf("Cannot deserialize json: %s", err)
	}

	jiraTicket := clair.JiraTicket{}

	for n, r := range reporters {
		for pkg, vuln := range klarReport.Vulnerabilities {
			repo := strings.SplitN(klarReport.Repo, "/", 2)[1]
			jiraTicket.Repo = repo
			jiraTicket.Package = pkg
			jiraTicket.Description = featuresToJSON(vuln)
			if err := r.Report(jiraTicket); err != nil {
				log.Printf("Cannot generate report with %s: %s", n, err)
			}
		}
	}
}

func featuresToJSON(features []*clair.Feature) string {
	var output string
	featuresJSON := make([]string, 0)
	for _, f := range features {
		tmpstring, err := json.Marshal(f)
		if err != nil {

		}
		featuresJSON = append(featuresJSON, string(tmpstring))
	}
	output = strings.Join(featuresJSON, "\n")
	return output
}

func makeReporters() (map[string]reporter.Reporter, error) {
	reporters := map[string]reporter.Reporter{}

	n := "jira"
	maker, err := reporter.MakerByName(n)
	if err != nil {
		return nil, fmt.Errorf("cannot find reporter by name %q: %s", n, err)
	}

	r, err := maker.Make()
	if err != nil {
		return nil, fmt.Errorf("cannot create reporter by name %q: %s", n, err)
	}

	reporters[n] = r

	return reporters, nil
}
