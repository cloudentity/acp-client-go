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

// RejectInternationalPaymentConsentSystemReader is a Reader for the RejectInternationalPaymentConsentSystem structure.
type RejectInternationalPaymentConsentSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RejectInternationalPaymentConsentSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRejectInternationalPaymentConsentSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewRejectInternationalPaymentConsentSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRejectInternationalPaymentConsentSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRejectInternationalPaymentConsentSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewRejectInternationalPaymentConsentSystemOK creates a RejectInternationalPaymentConsentSystemOK with default headers values
func NewRejectInternationalPaymentConsentSystemOK() *RejectInternationalPaymentConsentSystemOK {
	return &RejectInternationalPaymentConsentSystemOK{}
}

/* RejectInternationalPaymentConsentSystemOK describes a response with status code 200, with default header values.

ConsentRejected
*/
type RejectInternationalPaymentConsentSystemOK struct {
	Payload *models.ConsentRejected
}

func (o *RejectInternationalPaymentConsentSystemOK) Error() string {
	return fmt.Sprintf("[POST /api/system/{tid}/open-banking/international-payment-consent/{login}/reject][%d] rejectInternationalPaymentConsentSystemOK  %+v", 200, o.Payload)
}
func (o *RejectInternationalPaymentConsentSystemOK) GetPayload() *models.ConsentRejected {
	return o.Payload
}

func (o *RejectInternationalPaymentConsentSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ConsentRejected)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectInternationalPaymentConsentSystemUnauthorized creates a RejectInternationalPaymentConsentSystemUnauthorized with default headers values
func NewRejectInternationalPaymentConsentSystemUnauthorized() *RejectInternationalPaymentConsentSystemUnauthorized {
	return &RejectInternationalPaymentConsentSystemUnauthorized{}
}

/* RejectInternationalPaymentConsentSystemUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type RejectInternationalPaymentConsentSystemUnauthorized struct {
	Payload *models.Error
}

func (o *RejectInternationalPaymentConsentSystemUnauthorized) Error() string {
	return fmt.Sprintf("[POST /api/system/{tid}/open-banking/international-payment-consent/{login}/reject][%d] rejectInternationalPaymentConsentSystemUnauthorized  %+v", 401, o.Payload)
}
func (o *RejectInternationalPaymentConsentSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectInternationalPaymentConsentSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectInternationalPaymentConsentSystemForbidden creates a RejectInternationalPaymentConsentSystemForbidden with default headers values
func NewRejectInternationalPaymentConsentSystemForbidden() *RejectInternationalPaymentConsentSystemForbidden {
	return &RejectInternationalPaymentConsentSystemForbidden{}
}

/* RejectInternationalPaymentConsentSystemForbidden describes a response with status code 403, with default header values.

HttpError
*/
type RejectInternationalPaymentConsentSystemForbidden struct {
	Payload *models.Error
}

func (o *RejectInternationalPaymentConsentSystemForbidden) Error() string {
	return fmt.Sprintf("[POST /api/system/{tid}/open-banking/international-payment-consent/{login}/reject][%d] rejectInternationalPaymentConsentSystemForbidden  %+v", 403, o.Payload)
}
func (o *RejectInternationalPaymentConsentSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectInternationalPaymentConsentSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectInternationalPaymentConsentSystemNotFound creates a RejectInternationalPaymentConsentSystemNotFound with default headers values
func NewRejectInternationalPaymentConsentSystemNotFound() *RejectInternationalPaymentConsentSystemNotFound {
	return &RejectInternationalPaymentConsentSystemNotFound{}
}

/* RejectInternationalPaymentConsentSystemNotFound describes a response with status code 404, with default header values.

HttpError
*/
type RejectInternationalPaymentConsentSystemNotFound struct {
	Payload *models.Error
}

func (o *RejectInternationalPaymentConsentSystemNotFound) Error() string {
	return fmt.Sprintf("[POST /api/system/{tid}/open-banking/international-payment-consent/{login}/reject][%d] rejectInternationalPaymentConsentSystemNotFound  %+v", 404, o.Payload)
}
func (o *RejectInternationalPaymentConsentSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectInternationalPaymentConsentSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
