// Code generated by go-swagger; DO NOT EDIT.

package openbanking_b_r

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/models"
)

// CreateDataAccessConsentReader is a Reader for the CreateDataAccessConsent structure.
type CreateDataAccessConsentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateDataAccessConsentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateDataAccessConsentCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateDataAccessConsentBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateDataAccessConsentUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateDataAccessConsentForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewCreateDataAccessConsentMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewCreateDataAccessConsentNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewCreateDataAccessConsentUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateDataAccessConsentUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateDataAccessConsentTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCreateDataAccessConsentInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewCreateDataAccessConsentCreated creates a CreateDataAccessConsentCreated with default headers values
func NewCreateDataAccessConsentCreated() *CreateDataAccessConsentCreated {
	return &CreateDataAccessConsentCreated{}
}

/* CreateDataAccessConsentCreated describes a response with status code 201, with default header values.

OBBRCustomerDataAccessConsentResponse
*/
type CreateDataAccessConsentCreated struct {
	Payload *models.OBBRCustomerDataAccessConsentResponse
}

func (o *CreateDataAccessConsentCreated) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/open-banking-brasil/open-banking/consents/v1/consents][%d] createDataAccessConsentCreated  %+v", 201, o.Payload)
}
func (o *CreateDataAccessConsentCreated) GetPayload() *models.OBBRCustomerDataAccessConsentResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRCustomerDataAccessConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentBadRequest creates a CreateDataAccessConsentBadRequest with default headers values
func NewCreateDataAccessConsentBadRequest() *CreateDataAccessConsentBadRequest {
	return &CreateDataAccessConsentBadRequest{}
}

/* CreateDataAccessConsentBadRequest describes a response with status code 400, with default header values.

OBBRErrorResponse
*/
type CreateDataAccessConsentBadRequest struct {
	Payload *models.OBBRErrorResponse
}

func (o *CreateDataAccessConsentBadRequest) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/open-banking-brasil/open-banking/consents/v1/consents][%d] createDataAccessConsentBadRequest  %+v", 400, o.Payload)
}
func (o *CreateDataAccessConsentBadRequest) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentUnauthorized creates a CreateDataAccessConsentUnauthorized with default headers values
func NewCreateDataAccessConsentUnauthorized() *CreateDataAccessConsentUnauthorized {
	return &CreateDataAccessConsentUnauthorized{}
}

/* CreateDataAccessConsentUnauthorized describes a response with status code 401, with default header values.

OBBRErrorResponse
*/
type CreateDataAccessConsentUnauthorized struct {
	Payload *models.OBBRErrorResponse
}

func (o *CreateDataAccessConsentUnauthorized) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/open-banking-brasil/open-banking/consents/v1/consents][%d] createDataAccessConsentUnauthorized  %+v", 401, o.Payload)
}
func (o *CreateDataAccessConsentUnauthorized) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentForbidden creates a CreateDataAccessConsentForbidden with default headers values
func NewCreateDataAccessConsentForbidden() *CreateDataAccessConsentForbidden {
	return &CreateDataAccessConsentForbidden{}
}

/* CreateDataAccessConsentForbidden describes a response with status code 403, with default header values.

OBBRErrorResponse
*/
type CreateDataAccessConsentForbidden struct {
	Payload *models.OBBRErrorResponse
}

func (o *CreateDataAccessConsentForbidden) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/open-banking-brasil/open-banking/consents/v1/consents][%d] createDataAccessConsentForbidden  %+v", 403, o.Payload)
}
func (o *CreateDataAccessConsentForbidden) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentMethodNotAllowed creates a CreateDataAccessConsentMethodNotAllowed with default headers values
func NewCreateDataAccessConsentMethodNotAllowed() *CreateDataAccessConsentMethodNotAllowed {
	return &CreateDataAccessConsentMethodNotAllowed{}
}

/* CreateDataAccessConsentMethodNotAllowed describes a response with status code 405, with default header values.

OBBRErrorResponse
*/
type CreateDataAccessConsentMethodNotAllowed struct {
	Payload *models.OBBRErrorResponse
}

func (o *CreateDataAccessConsentMethodNotAllowed) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/open-banking-brasil/open-banking/consents/v1/consents][%d] createDataAccessConsentMethodNotAllowed  %+v", 405, o.Payload)
}
func (o *CreateDataAccessConsentMethodNotAllowed) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentNotAcceptable creates a CreateDataAccessConsentNotAcceptable with default headers values
func NewCreateDataAccessConsentNotAcceptable() *CreateDataAccessConsentNotAcceptable {
	return &CreateDataAccessConsentNotAcceptable{}
}

/* CreateDataAccessConsentNotAcceptable describes a response with status code 406, with default header values.

OBBRErrorResponse
*/
type CreateDataAccessConsentNotAcceptable struct {
	Payload *models.OBBRErrorResponse
}

func (o *CreateDataAccessConsentNotAcceptable) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/open-banking-brasil/open-banking/consents/v1/consents][%d] createDataAccessConsentNotAcceptable  %+v", 406, o.Payload)
}
func (o *CreateDataAccessConsentNotAcceptable) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentUnsupportedMediaType creates a CreateDataAccessConsentUnsupportedMediaType with default headers values
func NewCreateDataAccessConsentUnsupportedMediaType() *CreateDataAccessConsentUnsupportedMediaType {
	return &CreateDataAccessConsentUnsupportedMediaType{}
}

/* CreateDataAccessConsentUnsupportedMediaType describes a response with status code 415, with default header values.

OBBRErrorResponse
*/
type CreateDataAccessConsentUnsupportedMediaType struct {
	Payload *models.OBBRErrorResponse
}

func (o *CreateDataAccessConsentUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/open-banking-brasil/open-banking/consents/v1/consents][%d] createDataAccessConsentUnsupportedMediaType  %+v", 415, o.Payload)
}
func (o *CreateDataAccessConsentUnsupportedMediaType) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentUnprocessableEntity creates a CreateDataAccessConsentUnprocessableEntity with default headers values
func NewCreateDataAccessConsentUnprocessableEntity() *CreateDataAccessConsentUnprocessableEntity {
	return &CreateDataAccessConsentUnprocessableEntity{}
}

/* CreateDataAccessConsentUnprocessableEntity describes a response with status code 422, with default header values.

OBBRErrorResponse
*/
type CreateDataAccessConsentUnprocessableEntity struct {
	Payload *models.OBBRErrorResponse
}

func (o *CreateDataAccessConsentUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/open-banking-brasil/open-banking/consents/v1/consents][%d] createDataAccessConsentUnprocessableEntity  %+v", 422, o.Payload)
}
func (o *CreateDataAccessConsentUnprocessableEntity) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentTooManyRequests creates a CreateDataAccessConsentTooManyRequests with default headers values
func NewCreateDataAccessConsentTooManyRequests() *CreateDataAccessConsentTooManyRequests {
	return &CreateDataAccessConsentTooManyRequests{}
}

/* CreateDataAccessConsentTooManyRequests describes a response with status code 429, with default header values.

OBBRErrorResponse
*/
type CreateDataAccessConsentTooManyRequests struct {
	Payload *models.OBBRErrorResponse
}

func (o *CreateDataAccessConsentTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/open-banking-brasil/open-banking/consents/v1/consents][%d] createDataAccessConsentTooManyRequests  %+v", 429, o.Payload)
}
func (o *CreateDataAccessConsentTooManyRequests) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentInternalServerError creates a CreateDataAccessConsentInternalServerError with default headers values
func NewCreateDataAccessConsentInternalServerError() *CreateDataAccessConsentInternalServerError {
	return &CreateDataAccessConsentInternalServerError{}
}

/* CreateDataAccessConsentInternalServerError describes a response with status code 500, with default header values.

OBBRErrorResponse
*/
type CreateDataAccessConsentInternalServerError struct {
	Payload *models.OBBRErrorResponse
}

func (o *CreateDataAccessConsentInternalServerError) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/open-banking-brasil/open-banking/consents/v1/consents][%d] createDataAccessConsentInternalServerError  %+v", 500, o.Payload)
}
func (o *CreateDataAccessConsentInternalServerError) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
