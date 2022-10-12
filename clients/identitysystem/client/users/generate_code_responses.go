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

// GenerateCodeReader is a Reader for the GenerateCode structure.
type GenerateCodeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GenerateCodeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewGenerateCodeCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGenerateCodeBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGenerateCodeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGenerateCodeNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewGenerateCodePreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewGenerateCodeUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGenerateCodeTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGenerateCodeCreated creates a GenerateCodeCreated with default headers values
func NewGenerateCodeCreated() *GenerateCodeCreated {
	return &GenerateCodeCreated{}
}

/*
GenerateCodeCreated describes a response with status code 201, with default header values.

User
*/
type GenerateCodeCreated struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.Codes
}

// IsSuccess returns true when this generate code created response has a 2xx status code
func (o *GenerateCodeCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this generate code created response has a 3xx status code
func (o *GenerateCodeCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this generate code created response has a 4xx status code
func (o *GenerateCodeCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this generate code created response has a 5xx status code
func (o *GenerateCodeCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this generate code created response a status code equal to that given
func (o *GenerateCodeCreated) IsCode(code int) bool {
	return code == 201
}

func (o *GenerateCodeCreated) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/code/generate][%d] generateCodeCreated  %+v", 201, o.Payload)
}

func (o *GenerateCodeCreated) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/code/generate][%d] generateCodeCreated  %+v", 201, o.Payload)
}

func (o *GenerateCodeCreated) GetPayload() *models.Codes {
	return o.Payload
}

func (o *GenerateCodeCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.Codes)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGenerateCodeBadRequest creates a GenerateCodeBadRequest with default headers values
func NewGenerateCodeBadRequest() *GenerateCodeBadRequest {
	return &GenerateCodeBadRequest{}
}

/*
GenerateCodeBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type GenerateCodeBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this generate code bad request response has a 2xx status code
func (o *GenerateCodeBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this generate code bad request response has a 3xx status code
func (o *GenerateCodeBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this generate code bad request response has a 4xx status code
func (o *GenerateCodeBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this generate code bad request response has a 5xx status code
func (o *GenerateCodeBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this generate code bad request response a status code equal to that given
func (o *GenerateCodeBadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *GenerateCodeBadRequest) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/code/generate][%d] generateCodeBadRequest  %+v", 400, o.Payload)
}

func (o *GenerateCodeBadRequest) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/code/generate][%d] generateCodeBadRequest  %+v", 400, o.Payload)
}

func (o *GenerateCodeBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *GenerateCodeBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGenerateCodeUnauthorized creates a GenerateCodeUnauthorized with default headers values
func NewGenerateCodeUnauthorized() *GenerateCodeUnauthorized {
	return &GenerateCodeUnauthorized{}
}

/*
GenerateCodeUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type GenerateCodeUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this generate code unauthorized response has a 2xx status code
func (o *GenerateCodeUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this generate code unauthorized response has a 3xx status code
func (o *GenerateCodeUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this generate code unauthorized response has a 4xx status code
func (o *GenerateCodeUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this generate code unauthorized response has a 5xx status code
func (o *GenerateCodeUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this generate code unauthorized response a status code equal to that given
func (o *GenerateCodeUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *GenerateCodeUnauthorized) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/code/generate][%d] generateCodeUnauthorized  %+v", 401, o.Payload)
}

func (o *GenerateCodeUnauthorized) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/code/generate][%d] generateCodeUnauthorized  %+v", 401, o.Payload)
}

func (o *GenerateCodeUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GenerateCodeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGenerateCodeNotFound creates a GenerateCodeNotFound with default headers values
func NewGenerateCodeNotFound() *GenerateCodeNotFound {
	return &GenerateCodeNotFound{}
}

/*
GenerateCodeNotFound describes a response with status code 404, with default header values.

HttpError
*/
type GenerateCodeNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this generate code not found response has a 2xx status code
func (o *GenerateCodeNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this generate code not found response has a 3xx status code
func (o *GenerateCodeNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this generate code not found response has a 4xx status code
func (o *GenerateCodeNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this generate code not found response has a 5xx status code
func (o *GenerateCodeNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this generate code not found response a status code equal to that given
func (o *GenerateCodeNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *GenerateCodeNotFound) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/code/generate][%d] generateCodeNotFound  %+v", 404, o.Payload)
}

func (o *GenerateCodeNotFound) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/code/generate][%d] generateCodeNotFound  %+v", 404, o.Payload)
}

func (o *GenerateCodeNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GenerateCodeNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGenerateCodePreconditionFailed creates a GenerateCodePreconditionFailed with default headers values
func NewGenerateCodePreconditionFailed() *GenerateCodePreconditionFailed {
	return &GenerateCodePreconditionFailed{}
}

/*
GenerateCodePreconditionFailed describes a response with status code 412, with default header values.

HttpError
*/
type GenerateCodePreconditionFailed struct {
	Payload *models.Error
}

// IsSuccess returns true when this generate code precondition failed response has a 2xx status code
func (o *GenerateCodePreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this generate code precondition failed response has a 3xx status code
func (o *GenerateCodePreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this generate code precondition failed response has a 4xx status code
func (o *GenerateCodePreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this generate code precondition failed response has a 5xx status code
func (o *GenerateCodePreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this generate code precondition failed response a status code equal to that given
func (o *GenerateCodePreconditionFailed) IsCode(code int) bool {
	return code == 412
}

func (o *GenerateCodePreconditionFailed) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/code/generate][%d] generateCodePreconditionFailed  %+v", 412, o.Payload)
}

func (o *GenerateCodePreconditionFailed) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/code/generate][%d] generateCodePreconditionFailed  %+v", 412, o.Payload)
}

func (o *GenerateCodePreconditionFailed) GetPayload() *models.Error {
	return o.Payload
}

func (o *GenerateCodePreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGenerateCodeUnprocessableEntity creates a GenerateCodeUnprocessableEntity with default headers values
func NewGenerateCodeUnprocessableEntity() *GenerateCodeUnprocessableEntity {
	return &GenerateCodeUnprocessableEntity{}
}

/*
GenerateCodeUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type GenerateCodeUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this generate code unprocessable entity response has a 2xx status code
func (o *GenerateCodeUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this generate code unprocessable entity response has a 3xx status code
func (o *GenerateCodeUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this generate code unprocessable entity response has a 4xx status code
func (o *GenerateCodeUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this generate code unprocessable entity response has a 5xx status code
func (o *GenerateCodeUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this generate code unprocessable entity response a status code equal to that given
func (o *GenerateCodeUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

func (o *GenerateCodeUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/code/generate][%d] generateCodeUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *GenerateCodeUnprocessableEntity) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/code/generate][%d] generateCodeUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *GenerateCodeUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *GenerateCodeUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGenerateCodeTooManyRequests creates a GenerateCodeTooManyRequests with default headers values
func NewGenerateCodeTooManyRequests() *GenerateCodeTooManyRequests {
	return &GenerateCodeTooManyRequests{}
}

/*
GenerateCodeTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type GenerateCodeTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this generate code too many requests response has a 2xx status code
func (o *GenerateCodeTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this generate code too many requests response has a 3xx status code
func (o *GenerateCodeTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this generate code too many requests response has a 4xx status code
func (o *GenerateCodeTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this generate code too many requests response has a 5xx status code
func (o *GenerateCodeTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this generate code too many requests response a status code equal to that given
func (o *GenerateCodeTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *GenerateCodeTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/code/generate][%d] generateCodeTooManyRequests  %+v", 429, o.Payload)
}

func (o *GenerateCodeTooManyRequests) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/code/generate][%d] generateCodeTooManyRequests  %+v", 429, o.Payload)
}

func (o *GenerateCodeTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GenerateCodeTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
