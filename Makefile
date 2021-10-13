swagger = docker run --rm -it -e GOPATH=/go \
			-u $(shell id -u ${USER}):$(shell id -g ${USER}) \
			-v $(shell pwd):/go/src \
			-w $(shell pwd)/src quay.io/goswagger/swagger

.PHONY: generate
generate: generate-acp generate-openbanking-uk generate-openbanking-brasil

.PHONY: generate-acp
generate-acp:
	rm -rf acp
	mkdir acp
	sed -i 's/flow: application/flow: accessCode/g' swagger-acp-client.yaml
	sed -i 's/flow: password/flow: accessCode/g' swagger-acp-client.yaml
	${swagger} generate client -f /go/src/swagger-acp-client.yaml -A acp -t /go/src/acp

.PHONY: generate-openbanking-uk
generate-openbanking-uk:
	rm -rf openbankingUK
	mkdir openbankingUK
	mkdir openbankingUK/{accounts,payments}
	${swagger} generate client -f /go/src/swagger-openbanking-uk-accounts-supported.yaml -A openbankingUKClient -t /go/src/openbankingUK/accounts
	${swagger} generate client -f /go/src/swagger-openbanking-uk-payments-supported.yaml -A openbankingUKClient -t /go/src/openbankingUK/payments

.PHONY: generate-openbanking-brasil
generate-openbanking-brasil:
	rm -rf openbankingBR
	mkdir openbankingBR
	mkdir openbankingBR/{consents,payments}
	${swagger} generate client -f /go/src/swagger-openbanking-brasil-consents-supported.yaml -A openbankingBRClient -t /go/src/openbankingBR/consents
	${swagger} generate client -f /go/src/swagger-openbanking-brasil-payments-supported.yaml -A openbankingBRClient -t /go/src/openbankingBR/payments	
