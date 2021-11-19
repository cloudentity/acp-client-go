swagger = docker run --rm -it -e GOPATH=/go \
			-u $(shell id -u ${USER}):$(shell id -g ${USER}) \
			-v $(shell pwd):/go/src \
			-w $(shell pwd)/src quay.io/goswagger/swagger

.PHONY: generate
generate: generate-acp generate-openbanking-uk generate-openbanking-brasil

.PHONY: generate-acp
generate-acp:
	rm -rf clients/acp
	mkdir clients/acp
	sed -i 's/flow: application/flow: accessCode/g' spec/swagger-acp-client.yaml
	sed -i 's/flow: password/flow: accessCode/g' spec/swagger-acp-client.yaml
	${swagger} generate client -f /go/src/spec/swagger-acp-client.yaml -A acp -t /go/src/clients/acp

.PHONY: generate-openbanking-uk
generate-openbanking-uk:
	rm -rf clients/openbankingUK
	mkdir -p clients/openbankingUK/accounts
	mkdir -p clients/openbankingUK/payments

	${swagger} generate client -f /go/src/spec/swagger-openbanking-uk-accounts-supported.yaml -A openbankingUKClient -t /go/src/clients/openbankingUK/accounts
	${swagger} generate client -f /go/src/spec/swagger-openbanking-uk-payments-supported.yaml -A openbankingUKClient -t /go/src/clients/openbankingUK/payments

.PHONY: generate-openbanking-brasil
generate-openbanking-brasil:
	rm -rf clients/openbankingBR
	mkdir -p clients/openbankingBR/consents
	mkdir -p clients/openbankingBR/payments

	${swagger} generate client -f /go/src/spec/swagger-openbanking-brasil-consents-supported.yaml -A openbankingBRClient -t /go/src/clients/openbankingBR/consents
	${swagger} generate client -f /go/src/spec/swagger-openbanking-brasil-payments-supported.yaml -A openbankingBRClient -t /go/src/clients/openbankingBR/payments	
