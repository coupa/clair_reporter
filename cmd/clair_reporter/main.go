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

var (
	jsonVulnerabilityReportFilePath string
	teamConfigFilePath              string
	defaultTeam                     string
	defaultAssignee                 string
	defaultVersion                  string
)

func init() {
	flag.StringVar(&jsonVulnerabilityReportFilePath, "file-path", "", "path to the JSON report from klar")
	flag.StringVar(&teamConfigFilePath, "team-path", "", "path to the JSON repository-team mapping")
	flag.StringVar(&defaultTeam, "default-team", "Review", "default team to assign tickets")
	flag.StringVar(&defaultAssignee, "default-assignee", "", "default assignee for tickets")
	flag.StringVar(&defaultVersion, "default-version", "master", "default version for ticket")
	reporter.RegisterFlags()
}

func main() {
	flag.Parse()
	fmt.Println(jsonVulnerabilityReportFilePath)
	if jsonVulnerabilityReportFilePath == "" {
		log.Fatalf("You must specify a path to the JSON file, pass --file-path <path to json file>")
		os.Exit(1)
	}
	repositoryTeams, repositoryAssignees, err := loadTeamConfig()
	if err != nil {
		log.Fatalf("Cannot load team config: %s", err)
	}
	reporters, err := makeReporters()
	if err != nil {
		log.Fatalf("Cannot create requested reporters: %s", err)
	}

	file, err := os.Open(jsonVulnerabilityReportFilePath)
	if err != nil {
		log.Fatalf("Cannot open JSON file %s: %s", jsonVulnerabilityReportFilePath, err)
	}
	defer file.Close()

	reportClairFindings(file, repositoryTeams, repositoryAssignees, reporters)
}

func reportClairFindings(file *os.File, repositoryTeams, repositoryAssignees map[string]string, reporters map[string]reporter.Reporter) {
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
			priority := "P2"
			severity := "Sev-2"
			for _, feature := range vuln {
				if feature.Severity == "Critical" ||
					feature.Severity == "Defcon1" {
					priority = "P1"
					severity = "Sev-1"
					break
				}
			}
			jiraTicket.Description = featuresToJSON(vuln)
			devTeam := repositoryTeams[repo]
			if devTeam == "" {
				devTeam = defaultTeam
			}
			devAssignee := repositoryAssignees[repo]
			if devAssignee == "" {
				devAssignee = defaultAssignee
			}
			jiraTicket.DevTeam = devTeam
			jiraTicket.Assignee = devAssignee
			jiraTicket.Priority = priority
			jiraTicket.Severity = severity
			jiraTicket.Version = defaultVersion
			if err := r.Report(jiraTicket); err != nil {
				log.Printf("Cannot generate report with %s: %s", n, err)
			}
		}
	}
}

func loadTeamConfig() (map[string]string, map[string]string, error) {
	if teamConfigFilePath == "" {
		return nil, nil, fmt.Errorf("missing path to JSON file, pass --team-path <path to json file>")
	}
	teamConfigFile, err := os.Open(teamConfigFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot open file:%s err:%s", teamConfigFilePath, err)
	}
	defer teamConfigFile.Close()

	teamRepositories := []*clair.TeamRepositories{}
	data, err := ioutil.ReadAll(teamConfigFile)
	if err != nil {
		log.Printf("Cannot read json file: %s", err)
	}

	json.Unmarshal(data, &teamRepositories)
	if err != nil {
		log.Printf("Cannot deserialize json: %s", err)
	}

	repositoryTeams := make(map[string]string)
	repositoryAssignees := make(map[string]string)
	for _, tr := range teamRepositories {
		repositoryTeams[tr.Repo] = tr.Team
		repositoryAssignees[tr.Repo] = tr.Assignee
	}
	return repositoryTeams, repositoryAssignees, nil
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
	output = strings.Join(featuresJSON, "\\\\")
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
