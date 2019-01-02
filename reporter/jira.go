package reporter

import (
	"flag"
	"fmt"
	"io/ioutil"
	"strings"

	"clair_reporter/clair"

	jira "github.com/andygrunwald/go-jira"
)

// jiraReporter holds necessary information to create issues for any failures
type jiraReporter struct {
	client           *jira.Client
	metaProject      *jira.MetaProject
	metaIssuetype    *jira.MetaIssueType
	fieldsConfig     map[string]string
	closedStatusName string
}

func init() {
	var (
		jiraURL             *string
		username            *string
		token               *string
		fieldsConfiguration *string
		closedStatus        *string
	)

	registerMaker("jira", Maker{
		RegisterFlags: func() {
			jiraURL = flag.String("JIRA_URL", "", "Default JIRA instance url")
			username = flag.String("JIRA_USERNAME", "", "JIRA user to authenticate as")
			token = flag.String("JIRA_TOKEN", "", "JIRA token for the user to authenticate")
			// TODO: Turn this into a file-path argument to use a template file instead of string
			fieldsConfiguration = flag.String("JIRA_FIELDS", "Project|CD;Issue Type|Bug;Summary|Container Security Vulnerability: container name:{{ .failure.Repo }}, package name:{{ .failure.Package }};Description|{{ .failure.Description }};Component/s|Platform Security;Dev Team|{{ .failure.DevTeam }};Assignee|{{ .failure.Assignee }};Priority|{{ .failure.Priority }};Severity|{{ .failure.Severity }};Vulnerability Report By|Clair;Labels|security_infrastructure", "JIRA fields in 'key|value;...' format seperated by ';', this configuration MUST contain 'Project', 'Summary' and 'Issue Type'")
			closedStatus = flag.String("JIRA_ISSUE_CLOSED_STATUS", "Closed", "The status of JIRA issue when it is considered closed")
		},

		Make: func() (Reporter, error) {
			return newJiraReporter(*jiraURL, *username, *token, *fieldsConfiguration, *closedStatus)
		},
	})
}

func newJiraReporter(jiraURL, username, token, fieldsConfiguration, closedStatus string) (*jiraReporter, error) {
	err := checkArgsNotNil(jiraURL, username, token, fieldsConfiguration, closedStatus)
	if err != nil {
		return nil, err
	}

	reporter := new(jiraReporter)
	client, err := createJiraClient(jiraURL, username, token)
	if err != nil {
		return nil, err
	}

	reporter.client = client

	err = reporter.setFieldsConfig(fieldsConfiguration)
	if err != nil {
		return nil, err
	}

	project, found := reporter.fieldsConfig["Project"]
	if !found {
		return nil, fmt.Errorf("project is equired in field configuration")
	}

	issueType, found := reporter.fieldsConfig["Issue Type"]
	if !found {
		return nil, fmt.Errorf("issue type is required in field configuration")
	}

	reporter.closedStatusName = closedStatus

	// get create meta information
	metaProject, err := createMetaProject(client, project)
	if err != nil {
		return nil, err
	}

	reporter.metaProject = metaProject

	// get right issue within project
	metaIssuetype, err := createMetaIssueType(metaProject, issueType)
	if err != nil {
		return nil, err
	}

	// check if the given fields completes the mandatory fields and all listed fields are available
	complete, err := metaIssuetype.CheckCompleteAndAvailable(reporter.fieldsConfig)
	if !complete {
		return nil, err
	}

	reporter.metaIssuetype = metaIssuetype
	return reporter, nil
}

// Todo: change the failure object into a clair vuln report
func (j *jiraReporter) Report(report clair.JiraTicket) error {
	renderedFields := make(map[string]string)
	// render all values as they can be templates
	for field, templatedValue := range j.fieldsConfig {
		rendered, err := fillTemplate(report, templatedValue)
		if err != nil {
			return fmt.Errorf("rendering value of %s as template failed: %s", field, err)
		}
		renderedFields[field] = rendered
	}

	// generate jql with exact match for summary, project and status
	query := fmt.Sprintf(`summary ~ "\"%s\"" AND project = %s AND status != %s`, renderedFields["Summary"], renderedFields["Project"], j.closedStatusName)
	results, resp, err := j.client.Issue.Search(query, nil)
	if err != nil {
		return fmt.Errorf(readJiraReponse(resp))
	}

	if len(results) != 0 {
		// there were issues not closed.
		// Don't create a new one
		return nil
	}

	issue, err := jira.InitIssueWithMetaAndFields(j.metaProject, j.metaIssuetype, renderedFields)
	if err != nil {
		return fmt.Errorf("could not initialize issue: %s", err)
	}

	issue, resp, err = j.client.Issue.Create(issue)
	if err != nil {
		return fmt.Errorf(readJiraReponse(resp))
	}

	user, resp, err := j.client.User.Get(report.Assignee)
	if err != nil {
		return fmt.Errorf(readJiraReponse(resp))
	}

	resp, err = j.client.Issue.UpdateAssignee(issue.ID, user)
	if err != nil {
		return fmt.Errorf(readJiraReponse(resp))
	}

	return nil
}

// setFieldsConfig gets the fields string in format key:value;key2:value;...
// Seperate them and create a map.
func (j *jiraReporter) setFieldsConfig(fieldsConfiguration string) error {
	fields := strings.Split(fieldsConfiguration, ";")
	templateConfig := make(map[string]string)
	for _, directive := range fields {
		keyValueArr := strings.Split(directive, "|")
		if len(keyValueArr) != 2 {
			return fmt.Errorf("invalid field configuration: expected in key:value format, not %s", directive)
		}
		templateConfig[keyValueArr[0]] = keyValueArr[1]
	}
	j.fieldsConfig = templateConfig
	return nil
}

func getAllIssueTypeNames(project *jira.MetaProject) []string {
	var foundIssueTypes []string
	for _, m := range project.IssueTypes {
		foundIssueTypes = append(foundIssueTypes, m.Name)
	}
	return foundIssueTypes
}

func checkArgsNotNil(args ...string) error {
	for _, value := range args {
		if value == "" {
			return fmt.Errorf("all fields are necessary. Some of them are unfulfilled")
		}
	}
	return nil
}

func readJiraReponse(resp *jira.Response) string {
	if resp == nil || resp.Body == nil {
		return fmt.Sprintf("nil response or response body")
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	rawBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Sprintf("could not read response body. %s", err)
	}

	return fmt.Sprintf("could not create issue. Detailed information: %s", string(rawBody))
}

func createJiraClient(url, username, token string) (*jira.Client, error) {
	tp := jira.BasicAuthTransport{
		Username: username,
		Password: token,
	}

	jiraClient, err := jira.NewClient(tp.Client(), url)
	if err != nil {
		return nil, fmt.Errorf("could not create client: %s", err)
	}

	return jiraClient, nil
}

func createMetaProject(c *jira.Client, project string) (*jira.MetaProject, error) {
	meta, _, err := c.Issue.GetCreateMeta(project)
	if err != nil {
		return nil, fmt.Errorf("failed to get create meta : %s", err)
	}

	// get right project
	metaProject := meta.GetProjectWithKey(project)
	if metaProject == nil {
		return nil, fmt.Errorf("could not find project with key %s", project)
	}

	return metaProject, nil
}

func createMetaIssueType(metaProject *jira.MetaProject, issueType string) (*jira.MetaIssueType, error) {
	metaIssuetype := metaProject.GetIssueTypeWithName(issueType)
	if metaIssuetype == nil {
		return nil, fmt.Errorf("could not find issuetype %s, available are %#v", issueType, getAllIssueTypeNames(metaProject))
	}

	return metaIssuetype, nil
}
