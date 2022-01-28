// Code generated by go-swagger; DO NOT EDIT.

package openbanking_u_k

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/openbanking/models"
)

// CreateInternationalScheduledPaymentConsentRequestReader is a Reader for the CreateInternationalScheduledPaymentConsentRequest structure.
type CreateInternationalScheduledPaymentConsentRequestReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateInternationalScheduledPaymentConsentRequestReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateInternationalScheduledPaymentConsentRequestCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateInternationalScheduledPaymentConsentRequestBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateInternationalScheduledPaymentConsentRequestUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateInternationalScheduledPaymentConsentRequestForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewCreateInternationalScheduledPaymentConsentRequestMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewCreateInternationalScheduledPaymentConsentRequestNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewCreateInternationalScheduledPaymentConsentRequestUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateInternationalScheduledPaymentConsentRequestTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCreateInternationalScheduledPaymentConsentRequestInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewCreateInternationalScheduledPaymentConsentRequestCreated creates a CreateInternationalScheduledPaymentConsentRequestCreated with default headers values
func NewCreateInternationalScheduledPaymentConsentRequestCreated() *CreateInternationalScheduledPaymentConsentRequestCreated {
	return &CreateInternationalScheduledPaymentConsentRequestCreated{}
}

/* CreateInternationalScheduledPaymentConsentRequestCreated describes a response with status code 201, with default header values.

International scheduler payment consent
*/
type CreateInternationalScheduledPaymentConsentRequestCreated struct {
	Payload *models.InternationalScheduledPaymentConsentResponse
}

func (o *CreateInternationalScheduledPaymentConsentRequestCreated) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentRequestCreated  %+v", 201, o.Payload)
}
func (o *CreateInternationalScheduledPaymentConsentRequestCreated) GetPayload() *models.InternationalScheduledPaymentConsentResponse {
	return o.Payload
}

func (o *CreateInternationalScheduledPaymentConsentRequestCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.InternationalScheduledPaymentConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateInternationalScheduledPaymentConsentRequestBadRequest creates a CreateInternationalScheduledPaymentConsentRequestBadRequest with default headers values
func NewCreateInternationalScheduledPaymentConsentRequestBadRequest() *CreateInternationalScheduledPaymentConsentRequestBadRequest {
	return &CreateInternationalScheduledPaymentConsentRequestBadRequest{}
}

/* CreateInternationalScheduledPaymentConsentRequestBadRequest describes a response with status code 400, with default header values.

Error
*/
type CreateInternationalScheduledPaymentConsentRequestBadRequest struct {
	Payload *models.ErrorResponse
}

func (o *CreateInternationalScheduledPaymentConsentRequestBadRequest) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentRequestBadRequest  %+v", 400, o.Payload)
}
func (o *CreateInternationalScheduledPaymentConsentRequestBadRequest) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateInternationalScheduledPaymentConsentRequestBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateInternationalScheduledPaymentConsentRequestUnauthorized creates a CreateInternationalScheduledPaymentConsentRequestUnauthorized with default headers values
func NewCreateInternationalScheduledPaymentConsentRequestUnauthorized() *CreateInternationalScheduledPaymentConsentRequestUnauthorized {
	return &CreateInternationalScheduledPaymentConsentRequestUnauthorized{}
}

/* CreateInternationalScheduledPaymentConsentRequestUnauthorized describes a response with status code 401, with default header values.

Error
*/
type CreateInternationalScheduledPaymentConsentRequestUnauthorized struct {
	Payload *models.ErrorResponse
}

func (o *CreateInternationalScheduledPaymentConsentRequestUnauthorized) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentRequestUnauthorized  %+v", 401, o.Payload)
}
func (o *CreateInternationalScheduledPaymentConsentRequestUnauthorized) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateInternationalScheduledPaymentConsentRequestUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateInternationalScheduledPaymentConsentRequestForbidden creates a CreateInternationalScheduledPaymentConsentRequestForbidden with default headers values
func NewCreateInternationalScheduledPaymentConsentRequestForbidden() *CreateInternationalScheduledPaymentConsentRequestForbidden {
	return &CreateInternationalScheduledPaymentConsentRequestForbidden{}
}

/* CreateInternationalScheduledPaymentConsentRequestForbidden describes a response with status code 403, with default header values.

Error
*/
type CreateInternationalScheduledPaymentConsentRequestForbidden struct {
	Payload *models.ErrorResponse
}

func (o *CreateInternationalScheduledPaymentConsentRequestForbidden) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentRequestForbidden  %+v", 403, o.Payload)
}
func (o *CreateInternationalScheduledPaymentConsentRequestForbidden) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateInternationalScheduledPaymentConsentRequestForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateInternationalScheduledPaymentConsentRequestMethodNotAllowed creates a CreateInternationalScheduledPaymentConsentRequestMethodNotAllowed with default headers values
func NewCreateInternationalScheduledPaymentConsentRequestMethodNotAllowed() *CreateInternationalScheduledPaymentConsentRequestMethodNotAllowed {
	return &CreateInternationalScheduledPaymentConsentRequestMethodNotAllowed{}
}

/* CreateInternationalScheduledPaymentConsentRequestMethodNotAllowed describes a response with status code 405, with default header values.

Error
*/
type CreateInternationalScheduledPaymentConsentRequestMethodNotAllowed struct {
	Payload *models.ErrorResponse
}

func (o *CreateInternationalScheduledPaymentConsentRequestMethodNotAllowed) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentRequestMethodNotAllowed  %+v", 405, o.Payload)
}
func (o *CreateInternationalScheduledPaymentConsentRequestMethodNotAllowed) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateInternationalScheduledPaymentConsentRequestMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateInternationalScheduledPaymentConsentRequestNotAcceptable creates a CreateInternationalScheduledPaymentConsentRequestNotAcceptable with default headers values
func NewCreateInternationalScheduledPaymentConsentRequestNotAcceptable() *CreateInternationalScheduledPaymentConsentRequestNotAcceptable {
	return &CreateInternationalScheduledPaymentConsentRequestNotAcceptable{}
}

/* CreateInternationalScheduledPaymentConsentRequestNotAcceptable describes a response with status code 406, with default header values.

Error
*/
type CreateInternationalScheduledPaymentConsentRequestNotAcceptable struct {
	Payload *models.ErrorResponse
}

func (o *CreateInternationalScheduledPaymentConsentRequestNotAcceptable) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentRequestNotAcceptable  %+v", 406, o.Payload)
}
func (o *CreateInternationalScheduledPaymentConsentRequestNotAcceptable) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateInternationalScheduledPaymentConsentRequestNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateInternationalScheduledPaymentConsentRequestUnsupportedMediaType creates a CreateInternationalScheduledPaymentConsentRequestUnsupportedMediaType with default headers values
func NewCreateInternationalScheduledPaymentConsentRequestUnsupportedMediaType() *CreateInternationalScheduledPaymentConsentRequestUnsupportedMediaType {
	return &CreateInternationalScheduledPaymentConsentRequestUnsupportedMediaType{}
}

/* CreateInternationalScheduledPaymentConsentRequestUnsupportedMediaType describes a response with status code 415, with default header values.

Error
*/
type CreateInternationalScheduledPaymentConsentRequestUnsupportedMediaType struct {
	Payload *models.ErrorResponse
}

func (o *CreateInternationalScheduledPaymentConsentRequestUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentRequestUnsupportedMediaType  %+v", 415, o.Payload)
}
func (o *CreateInternationalScheduledPaymentConsentRequestUnsupportedMediaType) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateInternationalScheduledPaymentConsentRequestUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateInternationalScheduledPaymentConsentRequestTooManyRequests creates a CreateInternationalScheduledPaymentConsentRequestTooManyRequests with default headers values
func NewCreateInternationalScheduledPaymentConsentRequestTooManyRequests() *CreateInternationalScheduledPaymentConsentRequestTooManyRequests {
	return &CreateInternationalScheduledPaymentConsentRequestTooManyRequests{}
}

/* CreateInternationalScheduledPaymentConsentRequestTooManyRequests describes a response with status code 429, with default header values.

Error
*/
type CreateInternationalScheduledPaymentConsentRequestTooManyRequests struct {
	Payload *models.ErrorResponse
}

func (o *CreateInternationalScheduledPaymentConsentRequestTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentRequestTooManyRequests  %+v", 429, o.Payload)
}
func (o *CreateInternationalScheduledPaymentConsentRequestTooManyRequests) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateInternationalScheduledPaymentConsentRequestTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateInternationalScheduledPaymentConsentRequestInternalServerError creates a CreateInternationalScheduledPaymentConsentRequestInternalServerError with default headers values
func NewCreateInternationalScheduledPaymentConsentRequestInternalServerError() *CreateInternationalScheduledPaymentConsentRequestInternalServerError {
	return &CreateInternationalScheduledPaymentConsentRequestInternalServerError{}
}

/* CreateInternationalScheduledPaymentConsentRequestInternalServerError describes a response with status code 500, with default header values.

Error
*/
type CreateInternationalScheduledPaymentConsentRequestInternalServerError struct {
	Payload *models.ErrorResponse
}

func (o *CreateInternationalScheduledPaymentConsentRequestInternalServerError) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentRequestInternalServerError  %+v", 500, o.Payload)
}
func (o *CreateInternationalScheduledPaymentConsentRequestInternalServerError) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateInternationalScheduledPaymentConsentRequestInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}