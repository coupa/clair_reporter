# clair_reporter

debugging with delve:
dlv debug ~/src/gocode/src/clair_reporter/cmd/clair_reporter/main.go --output clair_reporter_debug  -- --JIRA_URL=https://<your jira account>.atlassian.net --JIRA_USERNAME=<your username>@<your domain>.com --JIRA_PASSWORD=<your api key>

teamrepo.json looks like this
```json
[
{
"repo": "app",
"team": "platform"
"assignee": "platform lead"
},
{
"repo": "adp",
"team": "hr"
"assignee": "hr lead"
}
]
```
