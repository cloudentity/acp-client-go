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

// AcceptDomesticScheduledPaymentConsentSystemReader is a Reader for the AcceptDomesticScheduledPaymentConsentSystem structure.
type AcceptDomesticScheduledPaymentConsentSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AcceptDomesticScheduledPaymentConsentSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAcceptDomesticScheduledPaymentConsentSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewAcceptDomesticScheduledPaymentConsentSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewAcceptDomesticScheduledPaymentConsentSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewAcceptDomesticScheduledPaymentConsentSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewAcceptDomesticScheduledPaymentConsentSystemOK creates a AcceptDomesticScheduledPaymentConsentSystemOK with default headers values
func NewAcceptDomesticScheduledPaymentConsentSystemOK() *AcceptDomesticScheduledPaymentConsentSystemOK {
	return &AcceptDomesticScheduledPaymentConsentSystemOK{}
}

/* AcceptDomesticScheduledPaymentConsentSystemOK describes a response with status code 200, with default header values.

ConsentAccepted
*/
type AcceptDomesticScheduledPaymentConsentSystemOK struct {
	Payload *models.ConsentAccepted
}

func (o *AcceptDomesticScheduledPaymentConsentSystemOK) Error() string {
	return fmt.Sprintf("[POST /api/system/{tid}/open-banking/domestic-scheduled-payment-consent/{login}/accept][%d] acceptDomesticScheduledPaymentConsentSystemOK  %+v", 200, o.Payload)
}
func (o *AcceptDomesticScheduledPaymentConsentSystemOK) GetPayload() *models.ConsentAccepted {
	return o.Payload
}

func (o *AcceptDomesticScheduledPaymentConsentSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ConsentAccepted)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAcceptDomesticScheduledPaymentConsentSystemUnauthorized creates a AcceptDomesticScheduledPaymentConsentSystemUnauthorized with default headers values
func NewAcceptDomesticScheduledPaymentConsentSystemUnauthorized() *AcceptDomesticScheduledPaymentConsentSystemUnauthorized {
	return &AcceptDomesticScheduledPaymentConsentSystemUnauthorized{}
}

/* AcceptDomesticScheduledPaymentConsentSystemUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type AcceptDomesticScheduledPaymentConsentSystemUnauthorized struct {
	Payload *models.Error
}

func (o *AcceptDomesticScheduledPaymentConsentSystemUnauthorized) Error() string {
	return fmt.Sprintf("[POST /api/system/{tid}/open-banking/domestic-scheduled-payment-consent/{login}/accept][%d] acceptDomesticScheduledPaymentConsentSystemUnauthorized  %+v", 401, o.Payload)
}
func (o *AcceptDomesticScheduledPaymentConsentSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *AcceptDomesticScheduledPaymentConsentSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAcceptDomesticScheduledPaymentConsentSystemForbidden creates a AcceptDomesticScheduledPaymentConsentSystemForbidden with default headers values
func NewAcceptDomesticScheduledPaymentConsentSystemForbidden() *AcceptDomesticScheduledPaymentConsentSystemForbidden {
	return &AcceptDomesticScheduledPaymentConsentSystemForbidden{}
}

/* AcceptDomesticScheduledPaymentConsentSystemForbidden describes a response with status code 403, with default header values.

HttpError
*/
type AcceptDomesticScheduledPaymentConsentSystemForbidden struct {
	Payload *models.Error
}

func (o *AcceptDomesticScheduledPaymentConsentSystemForbidden) Error() string {
	return fmt.Sprintf("[POST /api/system/{tid}/open-banking/domestic-scheduled-payment-consent/{login}/accept][%d] acceptDomesticScheduledPaymentConsentSystemForbidden  %+v", 403, o.Payload)
}
func (o *AcceptDomesticScheduledPaymentConsentSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *AcceptDomesticScheduledPaymentConsentSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAcceptDomesticScheduledPaymentConsentSystemNotFound creates a AcceptDomesticScheduledPaymentConsentSystemNotFound with default headers values
func NewAcceptDomesticScheduledPaymentConsentSystemNotFound() *AcceptDomesticScheduledPaymentConsentSystemNotFound {
	return &AcceptDomesticScheduledPaymentConsentSystemNotFound{}
}

/* AcceptDomesticScheduledPaymentConsentSystemNotFound describes a response with status code 404, with default header values.

HttpError
*/
type AcceptDomesticScheduledPaymentConsentSystemNotFound struct {
	Payload *models.Error
}

func (o *AcceptDomesticScheduledPaymentConsentSystemNotFound) Error() string {
	return fmt.Sprintf("[POST /api/system/{tid}/open-banking/domestic-scheduled-payment-consent/{login}/accept][%d] acceptDomesticScheduledPaymentConsentSystemNotFound  %+v", 404, o.Payload)
}
func (o *AcceptDomesticScheduledPaymentConsentSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *AcceptDomesticScheduledPaymentConsentSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
