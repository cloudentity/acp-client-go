swagger = docker run --rm -it -e GOPATH=/go \
			-u $(shell id -u ${USER}):$(shell id -g ${USER}) \
			-v $(shell pwd):/go/src \
			-w $(shell pwd)/src quay.io/goswagger/swagger

.PHONY: generate
generate: generate-acp generate-openbanking-uk generate-openbanking-brasil

SWAGGERS = public root developer oauth2 system admin web
SWAGGER_TARGETS = $(addprefix swagger-,$(SWAGGERS))

generate-acp: $(SWAGGER_TARGETS)

# swagger-MODULE
$(SWAGGER_TARGETS):
	rm -rf clients/$(subst swagger-,,$@)
	mkdir clients/$(subst swagger-,,$@)

	sed -i 's/flow: application/flow: accessCode/g' spec/swagger-$(subst swagger-,,$@).yaml
	sed -i 's/flow: password/flow: accessCode/g' spec/swagger-$(subst swagger-,,$@).yaml
	${swagger} generate client -f /go/src/spec/swagger-$(subst swagger-,,$@).yaml -A acp -t /go/src/clients/$(subst swagger-,,$@)

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
