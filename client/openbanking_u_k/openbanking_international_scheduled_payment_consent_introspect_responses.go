// Code generated by go-swagger; DO NOT EDIT.

package openbanking_u_k

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/models"
)

// OpenbankingInternationalScheduledPaymentConsentIntrospectReader is a Reader for the OpenbankingInternationalScheduledPaymentConsentIntrospect structure.
type OpenbankingInternationalScheduledPaymentConsentIntrospectReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *OpenbankingInternationalScheduledPaymentConsentIntrospectReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewOpenbankingInternationalScheduledPaymentConsentIntrospectOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewOpenbankingInternationalScheduledPaymentConsentIntrospectUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewOpenbankingInternationalScheduledPaymentConsentIntrospectNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewOpenbankingInternationalScheduledPaymentConsentIntrospectOK creates a OpenbankingInternationalScheduledPaymentConsentIntrospectOK with default headers values
func NewOpenbankingInternationalScheduledPaymentConsentIntrospectOK() *OpenbankingInternationalScheduledPaymentConsentIntrospectOK {
	return &OpenbankingInternationalScheduledPaymentConsentIntrospectOK{}
}

/* OpenbankingInternationalScheduledPaymentConsentIntrospectOK describes a response with status code 200, with default header values.

IntrospectOpenbankingInternationalScheduledPaymentConsentResponse
*/
type OpenbankingInternationalScheduledPaymentConsentIntrospectOK struct {
	Payload *models.IntrospectOpenbankingInternationalScheduledPaymentConsentResponse
}

func (o *OpenbankingInternationalScheduledPaymentConsentIntrospectOK) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/open-banking/v3.1/pisp/international-scheduled-payment-consents/introspect][%d] openbankingInternationalScheduledPaymentConsentIntrospectOK  %+v", 200, o.Payload)
}
func (o *OpenbankingInternationalScheduledPaymentConsentIntrospectOK) GetPayload() *models.IntrospectOpenbankingInternationalScheduledPaymentConsentResponse {
	return o.Payload
}

func (o *OpenbankingInternationalScheduledPaymentConsentIntrospectOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.IntrospectOpenbankingInternationalScheduledPaymentConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewOpenbankingInternationalScheduledPaymentConsentIntrospectUnauthorized creates a OpenbankingInternationalScheduledPaymentConsentIntrospectUnauthorized with default headers values
func NewOpenbankingInternationalScheduledPaymentConsentIntrospectUnauthorized() *OpenbankingInternationalScheduledPaymentConsentIntrospectUnauthorized {
	return &OpenbankingInternationalScheduledPaymentConsentIntrospectUnauthorized{}
}

/* OpenbankingInternationalScheduledPaymentConsentIntrospectUnauthorized describes a response with status code 401, with default header values.

genericError
*/
type OpenbankingInternationalScheduledPaymentConsentIntrospectUnauthorized struct {
	Payload *models.GenericError
}

func (o *OpenbankingInternationalScheduledPaymentConsentIntrospectUnauthorized) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/open-banking/v3.1/pisp/international-scheduled-payment-consents/introspect][%d] openbankingInternationalScheduledPaymentConsentIntrospectUnauthorized  %+v", 401, o.Payload)
}
func (o *OpenbankingInternationalScheduledPaymentConsentIntrospectUnauthorized) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *OpenbankingInternationalScheduledPaymentConsentIntrospectUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewOpenbankingInternationalScheduledPaymentConsentIntrospectNotFound creates a OpenbankingInternationalScheduledPaymentConsentIntrospectNotFound with default headers values
func NewOpenbankingInternationalScheduledPaymentConsentIntrospectNotFound() *OpenbankingInternationalScheduledPaymentConsentIntrospectNotFound {
	return &OpenbankingInternationalScheduledPaymentConsentIntrospectNotFound{}
}

/* OpenbankingInternationalScheduledPaymentConsentIntrospectNotFound describes a response with status code 404, with default header values.

genericError
*/
type OpenbankingInternationalScheduledPaymentConsentIntrospectNotFound struct {
	Payload *models.GenericError
}

func (o *OpenbankingInternationalScheduledPaymentConsentIntrospectNotFound) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/open-banking/v3.1/pisp/international-scheduled-payment-consents/introspect][%d] openbankingInternationalScheduledPaymentConsentIntrospectNotFound  %+v", 404, o.Payload)
}
func (o *OpenbankingInternationalScheduledPaymentConsentIntrospectNotFound) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *OpenbankingInternationalScheduledPaymentConsentIntrospectNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
