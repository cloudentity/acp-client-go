// Code generated by go-swagger; DO NOT EDIT.

package users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identitysystem/models"
)

// CompleteResetWebAuthnReader is a Reader for the CompleteResetWebAuthn structure.
type CompleteResetWebAuthnReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CompleteResetWebAuthnReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewCompleteResetWebAuthnNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewCompleteResetWebAuthnUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewCompleteResetWebAuthnPreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCompleteResetWebAuthnUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /system/pools/{ipID}/user/webauthn/reset/complete] completeResetWebAuthn", response, response.Code())
	}
}

// NewCompleteResetWebAuthnNoContent creates a CompleteResetWebAuthnNoContent with default headers values
func NewCompleteResetWebAuthnNoContent() *CompleteResetWebAuthnNoContent {
	return &CompleteResetWebAuthnNoContent{}
}

/*
CompleteResetWebAuthnNoContent describes a response with status code 204, with default header values.

Request accepted
*/
type CompleteResetWebAuthnNoContent struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string
}

// IsSuccess returns true when this complete reset web authn no content response has a 2xx status code
func (o *CompleteResetWebAuthnNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this complete reset web authn no content response has a 3xx status code
func (o *CompleteResetWebAuthnNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this complete reset web authn no content response has a 4xx status code
func (o *CompleteResetWebAuthnNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this complete reset web authn no content response has a 5xx status code
func (o *CompleteResetWebAuthnNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this complete reset web authn no content response a status code equal to that given
func (o *CompleteResetWebAuthnNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the complete reset web authn no content response
func (o *CompleteResetWebAuthnNoContent) Code() int {
	return 204
}

func (o *CompleteResetWebAuthnNoContent) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/webauthn/reset/complete][%d] completeResetWebAuthnNoContent ", 204)
}

func (o *CompleteResetWebAuthnNoContent) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/webauthn/reset/complete][%d] completeResetWebAuthnNoContent ", 204)
}

func (o *CompleteResetWebAuthnNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	return nil
}

// NewCompleteResetWebAuthnUnauthorized creates a CompleteResetWebAuthnUnauthorized with default headers values
func NewCompleteResetWebAuthnUnauthorized() *CompleteResetWebAuthnUnauthorized {
	return &CompleteResetWebAuthnUnauthorized{}
}

/*
CompleteResetWebAuthnUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CompleteResetWebAuthnUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this complete reset web authn unauthorized response has a 2xx status code
func (o *CompleteResetWebAuthnUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this complete reset web authn unauthorized response has a 3xx status code
func (o *CompleteResetWebAuthnUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this complete reset web authn unauthorized response has a 4xx status code
func (o *CompleteResetWebAuthnUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this complete reset web authn unauthorized response has a 5xx status code
func (o *CompleteResetWebAuthnUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this complete reset web authn unauthorized response a status code equal to that given
func (o *CompleteResetWebAuthnUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the complete reset web authn unauthorized response
func (o *CompleteResetWebAuthnUnauthorized) Code() int {
	return 401
}

func (o *CompleteResetWebAuthnUnauthorized) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/webauthn/reset/complete][%d] completeResetWebAuthnUnauthorized  %+v", 401, o.Payload)
}

func (o *CompleteResetWebAuthnUnauthorized) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/webauthn/reset/complete][%d] completeResetWebAuthnUnauthorized  %+v", 401, o.Payload)
}

func (o *CompleteResetWebAuthnUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CompleteResetWebAuthnUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCompleteResetWebAuthnPreconditionFailed creates a CompleteResetWebAuthnPreconditionFailed with default headers values
func NewCompleteResetWebAuthnPreconditionFailed() *CompleteResetWebAuthnPreconditionFailed {
	return &CompleteResetWebAuthnPreconditionFailed{}
}

/*
CompleteResetWebAuthnPreconditionFailed describes a response with status code 412, with default header values.

Payload too large
*/
type CompleteResetWebAuthnPreconditionFailed struct {
	Payload *models.Error
}

// IsSuccess returns true when this complete reset web authn precondition failed response has a 2xx status code
func (o *CompleteResetWebAuthnPreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this complete reset web authn precondition failed response has a 3xx status code
func (o *CompleteResetWebAuthnPreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this complete reset web authn precondition failed response has a 4xx status code
func (o *CompleteResetWebAuthnPreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this complete reset web authn precondition failed response has a 5xx status code
func (o *CompleteResetWebAuthnPreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this complete reset web authn precondition failed response a status code equal to that given
func (o *CompleteResetWebAuthnPreconditionFailed) IsCode(code int) bool {
	return code == 412
}

// Code gets the status code for the complete reset web authn precondition failed response
func (o *CompleteResetWebAuthnPreconditionFailed) Code() int {
	return 412
}

func (o *CompleteResetWebAuthnPreconditionFailed) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/webauthn/reset/complete][%d] completeResetWebAuthnPreconditionFailed  %+v", 412, o.Payload)
}

func (o *CompleteResetWebAuthnPreconditionFailed) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/webauthn/reset/complete][%d] completeResetWebAuthnPreconditionFailed  %+v", 412, o.Payload)
}

func (o *CompleteResetWebAuthnPreconditionFailed) GetPayload() *models.Error {
	return o.Payload
}

func (o *CompleteResetWebAuthnPreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCompleteResetWebAuthnUnprocessableEntity creates a CompleteResetWebAuthnUnprocessableEntity with default headers values
func NewCompleteResetWebAuthnUnprocessableEntity() *CompleteResetWebAuthnUnprocessableEntity {
	return &CompleteResetWebAuthnUnprocessableEntity{}
}

/*
CompleteResetWebAuthnUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type CompleteResetWebAuthnUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this complete reset web authn unprocessable entity response has a 2xx status code
func (o *CompleteResetWebAuthnUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this complete reset web authn unprocessable entity response has a 3xx status code
func (o *CompleteResetWebAuthnUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this complete reset web authn unprocessable entity response has a 4xx status code
func (o *CompleteResetWebAuthnUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this complete reset web authn unprocessable entity response has a 5xx status code
func (o *CompleteResetWebAuthnUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this complete reset web authn unprocessable entity response a status code equal to that given
func (o *CompleteResetWebAuthnUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the complete reset web authn unprocessable entity response
func (o *CompleteResetWebAuthnUnprocessableEntity) Code() int {
	return 422
}

func (o *CompleteResetWebAuthnUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/webauthn/reset/complete][%d] completeResetWebAuthnUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CompleteResetWebAuthnUnprocessableEntity) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/webauthn/reset/complete][%d] completeResetWebAuthnUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CompleteResetWebAuthnUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CompleteResetWebAuthnUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
