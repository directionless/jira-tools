all:

build: build/jira_oauth.go
	go get github.com/andygrunwald/go-jira
	go get github.com/dghubble/oauth1
	go get golang.org/x/net/context
	go get gopkg.in/alecthomas/kingpin.v2
	go run jira_oauth.go 

build/jira_oauth.go: jira_oauth.go
	@mkdir -p build
	cp $< $@
	perl -pe 's/CONSUMER_KEY_HERE/`cat ..\/shared-secret.txt`/e' -i $@
	perl -pe 's/RSA_KEY_HERE/`cat ..\/demo.key`/e' -i $@
