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

// CreateFilePaymentConsentFileReader is a Reader for the CreateFilePaymentConsentFile structure.
type CreateFilePaymentConsentFileReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateFilePaymentConsentFileReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCreateFilePaymentConsentFileOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateFilePaymentConsentFileBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateFilePaymentConsentFileUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateFilePaymentConsentFileForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewCreateFilePaymentConsentFileMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewCreateFilePaymentConsentFileNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewCreateFilePaymentConsentFileUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateFilePaymentConsentFileTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCreateFilePaymentConsentFileInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewCreateFilePaymentConsentFileOK creates a CreateFilePaymentConsentFileOK with default headers values
func NewCreateFilePaymentConsentFileOK() *CreateFilePaymentConsentFileOK {
	return &CreateFilePaymentConsentFileOK{}
}

/* CreateFilePaymentConsentFileOK describes a response with status code 200, with default header values.

file created
*/
type CreateFilePaymentConsentFileOK struct {
}

func (o *CreateFilePaymentConsentFileOK) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] createFilePaymentConsentFileOK ", 200)
}

func (o *CreateFilePaymentConsentFileOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewCreateFilePaymentConsentFileBadRequest creates a CreateFilePaymentConsentFileBadRequest with default headers values
func NewCreateFilePaymentConsentFileBadRequest() *CreateFilePaymentConsentFileBadRequest {
	return &CreateFilePaymentConsentFileBadRequest{}
}

/* CreateFilePaymentConsentFileBadRequest describes a response with status code 400, with default header values.

ErrorResponse
*/
type CreateFilePaymentConsentFileBadRequest struct {
	Payload *models.ErrorResponse
}

func (o *CreateFilePaymentConsentFileBadRequest) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] createFilePaymentConsentFileBadRequest  %+v", 400, o.Payload)
}
func (o *CreateFilePaymentConsentFileBadRequest) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateFilePaymentConsentFileBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateFilePaymentConsentFileUnauthorized creates a CreateFilePaymentConsentFileUnauthorized with default headers values
func NewCreateFilePaymentConsentFileUnauthorized() *CreateFilePaymentConsentFileUnauthorized {
	return &CreateFilePaymentConsentFileUnauthorized{}
}

/* CreateFilePaymentConsentFileUnauthorized describes a response with status code 401, with default header values.

ErrorResponse
*/
type CreateFilePaymentConsentFileUnauthorized struct {
	Payload *models.ErrorResponse
}

func (o *CreateFilePaymentConsentFileUnauthorized) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] createFilePaymentConsentFileUnauthorized  %+v", 401, o.Payload)
}
func (o *CreateFilePaymentConsentFileUnauthorized) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateFilePaymentConsentFileUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateFilePaymentConsentFileForbidden creates a CreateFilePaymentConsentFileForbidden with default headers values
func NewCreateFilePaymentConsentFileForbidden() *CreateFilePaymentConsentFileForbidden {
	return &CreateFilePaymentConsentFileForbidden{}
}

/* CreateFilePaymentConsentFileForbidden describes a response with status code 403, with default header values.

ErrorResponse
*/
type CreateFilePaymentConsentFileForbidden struct {
	Payload *models.ErrorResponse
}

func (o *CreateFilePaymentConsentFileForbidden) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] createFilePaymentConsentFileForbidden  %+v", 403, o.Payload)
}
func (o *CreateFilePaymentConsentFileForbidden) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateFilePaymentConsentFileForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateFilePaymentConsentFileMethodNotAllowed creates a CreateFilePaymentConsentFileMethodNotAllowed with default headers values
func NewCreateFilePaymentConsentFileMethodNotAllowed() *CreateFilePaymentConsentFileMethodNotAllowed {
	return &CreateFilePaymentConsentFileMethodNotAllowed{}
}

/* CreateFilePaymentConsentFileMethodNotAllowed describes a response with status code 405, with default header values.

ErrorResponse
*/
type CreateFilePaymentConsentFileMethodNotAllowed struct {
	Payload *models.ErrorResponse
}

func (o *CreateFilePaymentConsentFileMethodNotAllowed) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] createFilePaymentConsentFileMethodNotAllowed  %+v", 405, o.Payload)
}
func (o *CreateFilePaymentConsentFileMethodNotAllowed) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateFilePaymentConsentFileMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateFilePaymentConsentFileNotAcceptable creates a CreateFilePaymentConsentFileNotAcceptable with default headers values
func NewCreateFilePaymentConsentFileNotAcceptable() *CreateFilePaymentConsentFileNotAcceptable {
	return &CreateFilePaymentConsentFileNotAcceptable{}
}

/* CreateFilePaymentConsentFileNotAcceptable describes a response with status code 406, with default header values.

ErrorResponse
*/
type CreateFilePaymentConsentFileNotAcceptable struct {
	Payload *models.ErrorResponse
}

func (o *CreateFilePaymentConsentFileNotAcceptable) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] createFilePaymentConsentFileNotAcceptable  %+v", 406, o.Payload)
}
func (o *CreateFilePaymentConsentFileNotAcceptable) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateFilePaymentConsentFileNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateFilePaymentConsentFileUnsupportedMediaType creates a CreateFilePaymentConsentFileUnsupportedMediaType with default headers values
func NewCreateFilePaymentConsentFileUnsupportedMediaType() *CreateFilePaymentConsentFileUnsupportedMediaType {
	return &CreateFilePaymentConsentFileUnsupportedMediaType{}
}

/* CreateFilePaymentConsentFileUnsupportedMediaType describes a response with status code 415, with default header values.

ErrorResponse
*/
type CreateFilePaymentConsentFileUnsupportedMediaType struct {
	Payload *models.ErrorResponse
}

func (o *CreateFilePaymentConsentFileUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] createFilePaymentConsentFileUnsupportedMediaType  %+v", 415, o.Payload)
}
func (o *CreateFilePaymentConsentFileUnsupportedMediaType) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateFilePaymentConsentFileUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateFilePaymentConsentFileTooManyRequests creates a CreateFilePaymentConsentFileTooManyRequests with default headers values
func NewCreateFilePaymentConsentFileTooManyRequests() *CreateFilePaymentConsentFileTooManyRequests {
	return &CreateFilePaymentConsentFileTooManyRequests{}
}

/* CreateFilePaymentConsentFileTooManyRequests describes a response with status code 429, with default header values.

ErrorResponse
*/
type CreateFilePaymentConsentFileTooManyRequests struct {
	Payload *models.ErrorResponse
}

func (o *CreateFilePaymentConsentFileTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] createFilePaymentConsentFileTooManyRequests  %+v", 429, o.Payload)
}
func (o *CreateFilePaymentConsentFileTooManyRequests) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateFilePaymentConsentFileTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateFilePaymentConsentFileInternalServerError creates a CreateFilePaymentConsentFileInternalServerError with default headers values
func NewCreateFilePaymentConsentFileInternalServerError() *CreateFilePaymentConsentFileInternalServerError {
	return &CreateFilePaymentConsentFileInternalServerError{}
}

/* CreateFilePaymentConsentFileInternalServerError describes a response with status code 500, with default header values.

ErrorResponse
*/
type CreateFilePaymentConsentFileInternalServerError struct {
	Payload *models.ErrorResponse
}

func (o *CreateFilePaymentConsentFileInternalServerError) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] createFilePaymentConsentFileInternalServerError  %+v", 500, o.Payload)
}
func (o *CreateFilePaymentConsentFileInternalServerError) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateFilePaymentConsentFileInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
