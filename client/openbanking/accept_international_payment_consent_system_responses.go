// Code generated by go-swagger; DO NOT EDIT.

package openbanking

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/models"
)

// AcceptInternationalPaymentConsentSystemReader is a Reader for the AcceptInternationalPaymentConsentSystem structure.
type AcceptInternationalPaymentConsentSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AcceptInternationalPaymentConsentSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAcceptInternationalPaymentConsentSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewAcceptInternationalPaymentConsentSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewAcceptInternationalPaymentConsentSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewAcceptInternationalPaymentConsentSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewAcceptInternationalPaymentConsentSystemOK creates a AcceptInternationalPaymentConsentSystemOK with default headers values
func NewAcceptInternationalPaymentConsentSystemOK() *AcceptInternationalPaymentConsentSystemOK {
	return &AcceptInternationalPaymentConsentSystemOK{}
}

/* AcceptInternationalPaymentConsentSystemOK describes a response with status code 200, with default header values.

ConsentAccepted
*/
type AcceptInternationalPaymentConsentSystemOK struct {
	Payload *models.ConsentAccepted
}

func (o *AcceptInternationalPaymentConsentSystemOK) Error() string {
	return fmt.Sprintf("[POST /api/system/{tid}/open-banking/international-payment-consent/{login}/accept][%d] acceptInternationalPaymentConsentSystemOK  %+v", 200, o.Payload)
}
func (o *AcceptInternationalPaymentConsentSystemOK) GetPayload() *models.ConsentAccepted {
	return o.Payload
}

func (o *AcceptInternationalPaymentConsentSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ConsentAccepted)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAcceptInternationalPaymentConsentSystemUnauthorized creates a AcceptInternationalPaymentConsentSystemUnauthorized with default headers values
func NewAcceptInternationalPaymentConsentSystemUnauthorized() *AcceptInternationalPaymentConsentSystemUnauthorized {
	return &AcceptInternationalPaymentConsentSystemUnauthorized{}
}

/* AcceptInternationalPaymentConsentSystemUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type AcceptInternationalPaymentConsentSystemUnauthorized struct {
	Payload *models.Error
}

func (o *AcceptInternationalPaymentConsentSystemUnauthorized) Error() string {
	return fmt.Sprintf("[POST /api/system/{tid}/open-banking/international-payment-consent/{login}/accept][%d] acceptInternationalPaymentConsentSystemUnauthorized  %+v", 401, o.Payload)
}
func (o *AcceptInternationalPaymentConsentSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *AcceptInternationalPaymentConsentSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAcceptInternationalPaymentConsentSystemForbidden creates a AcceptInternationalPaymentConsentSystemForbidden with default headers values
func NewAcceptInternationalPaymentConsentSystemForbidden() *AcceptInternationalPaymentConsentSystemForbidden {
	return &AcceptInternationalPaymentConsentSystemForbidden{}
}

/* AcceptInternationalPaymentConsentSystemForbidden describes a response with status code 403, with default header values.

HttpError
*/
type AcceptInternationalPaymentConsentSystemForbidden struct {
	Payload *models.Error
}

func (o *AcceptInternationalPaymentConsentSystemForbidden) Error() string {
	return fmt.Sprintf("[POST /api/system/{tid}/open-banking/international-payment-consent/{login}/accept][%d] acceptInternationalPaymentConsentSystemForbidden  %+v", 403, o.Payload)
}
func (o *AcceptInternationalPaymentConsentSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *AcceptInternationalPaymentConsentSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAcceptInternationalPaymentConsentSystemNotFound creates a AcceptInternationalPaymentConsentSystemNotFound with default headers values
func NewAcceptInternationalPaymentConsentSystemNotFound() *AcceptInternationalPaymentConsentSystemNotFound {
	return &AcceptInternationalPaymentConsentSystemNotFound{}
}

/* AcceptInternationalPaymentConsentSystemNotFound describes a response with status code 404, with default header values.

HttpError
*/
type AcceptInternationalPaymentConsentSystemNotFound struct {
	Payload *models.Error
}

func (o *AcceptInternationalPaymentConsentSystemNotFound) Error() string {
	return fmt.Sprintf("[POST /api/system/{tid}/open-banking/international-payment-consent/{login}/accept][%d] acceptInternationalPaymentConsentSystemNotFound  %+v", 404, o.Payload)
}
func (o *AcceptInternationalPaymentConsentSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *AcceptInternationalPaymentConsentSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
