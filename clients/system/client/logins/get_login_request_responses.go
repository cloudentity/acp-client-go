// Code generated by go-swagger; DO NOT EDIT.

package logins

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/system/models"
)

// GetLoginRequestReader is a Reader for the GetLoginRequest structure.
type GetLoginRequestReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetLoginRequestReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetLoginRequestOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetLoginRequestUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetLoginRequestForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetLoginRequestNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetLoginRequestTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetLoginRequestOK creates a GetLoginRequestOK with default headers values
func NewGetLoginRequestOK() *GetLoginRequestOK {
	return &GetLoginRequestOK{}
}

/*
GetLoginRequestOK describes a response with status code 200, with default header values.

Login session
*/
type GetLoginRequestOK struct {
	Payload *models.LoginSessionResponse
}

// IsSuccess returns true when this get login request o k response has a 2xx status code
func (o *GetLoginRequestOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get login request o k response has a 3xx status code
func (o *GetLoginRequestOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get login request o k response has a 4xx status code
func (o *GetLoginRequestOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get login request o k response has a 5xx status code
func (o *GetLoginRequestOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get login request o k response a status code equal to that given
func (o *GetLoginRequestOK) IsCode(code int) bool {
	return code == 200
}

func (o *GetLoginRequestOK) Error() string {
	return fmt.Sprintf("[GET /logins/{login}][%d] getLoginRequestOK  %+v", 200, o.Payload)
}

func (o *GetLoginRequestOK) String() string {
	return fmt.Sprintf("[GET /logins/{login}][%d] getLoginRequestOK  %+v", 200, o.Payload)
}

func (o *GetLoginRequestOK) GetPayload() *models.LoginSessionResponse {
	return o.Payload
}

func (o *GetLoginRequestOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.LoginSessionResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetLoginRequestUnauthorized creates a GetLoginRequestUnauthorized with default headers values
func NewGetLoginRequestUnauthorized() *GetLoginRequestUnauthorized {
	return &GetLoginRequestUnauthorized{}
}

/*
GetLoginRequestUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type GetLoginRequestUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get login request unauthorized response has a 2xx status code
func (o *GetLoginRequestUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get login request unauthorized response has a 3xx status code
func (o *GetLoginRequestUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get login request unauthorized response has a 4xx status code
func (o *GetLoginRequestUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get login request unauthorized response has a 5xx status code
func (o *GetLoginRequestUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get login request unauthorized response a status code equal to that given
func (o *GetLoginRequestUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *GetLoginRequestUnauthorized) Error() string {
	return fmt.Sprintf("[GET /logins/{login}][%d] getLoginRequestUnauthorized  %+v", 401, o.Payload)
}

func (o *GetLoginRequestUnauthorized) String() string {
	return fmt.Sprintf("[GET /logins/{login}][%d] getLoginRequestUnauthorized  %+v", 401, o.Payload)
}

func (o *GetLoginRequestUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetLoginRequestUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetLoginRequestForbidden creates a GetLoginRequestForbidden with default headers values
func NewGetLoginRequestForbidden() *GetLoginRequestForbidden {
	return &GetLoginRequestForbidden{}
}

/*
GetLoginRequestForbidden describes a response with status code 403, with default header values.

HttpError
*/
type GetLoginRequestForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get login request forbidden response has a 2xx status code
func (o *GetLoginRequestForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get login request forbidden response has a 3xx status code
func (o *GetLoginRequestForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get login request forbidden response has a 4xx status code
func (o *GetLoginRequestForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get login request forbidden response has a 5xx status code
func (o *GetLoginRequestForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get login request forbidden response a status code equal to that given
func (o *GetLoginRequestForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *GetLoginRequestForbidden) Error() string {
	return fmt.Sprintf("[GET /logins/{login}][%d] getLoginRequestForbidden  %+v", 403, o.Payload)
}

func (o *GetLoginRequestForbidden) String() string {
	return fmt.Sprintf("[GET /logins/{login}][%d] getLoginRequestForbidden  %+v", 403, o.Payload)
}

func (o *GetLoginRequestForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetLoginRequestForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetLoginRequestNotFound creates a GetLoginRequestNotFound with default headers values
func NewGetLoginRequestNotFound() *GetLoginRequestNotFound {
	return &GetLoginRequestNotFound{}
}

/*
GetLoginRequestNotFound describes a response with status code 404, with default header values.

HttpError
*/
type GetLoginRequestNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get login request not found response has a 2xx status code
func (o *GetLoginRequestNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get login request not found response has a 3xx status code
func (o *GetLoginRequestNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get login request not found response has a 4xx status code
func (o *GetLoginRequestNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get login request not found response has a 5xx status code
func (o *GetLoginRequestNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get login request not found response a status code equal to that given
func (o *GetLoginRequestNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *GetLoginRequestNotFound) Error() string {
	return fmt.Sprintf("[GET /logins/{login}][%d] getLoginRequestNotFound  %+v", 404, o.Payload)
}

func (o *GetLoginRequestNotFound) String() string {
	return fmt.Sprintf("[GET /logins/{login}][%d] getLoginRequestNotFound  %+v", 404, o.Payload)
}

func (o *GetLoginRequestNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetLoginRequestNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetLoginRequestTooManyRequests creates a GetLoginRequestTooManyRequests with default headers values
func NewGetLoginRequestTooManyRequests() *GetLoginRequestTooManyRequests {
	return &GetLoginRequestTooManyRequests{}
}

/*
GetLoginRequestTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type GetLoginRequestTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get login request too many requests response has a 2xx status code
func (o *GetLoginRequestTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get login request too many requests response has a 3xx status code
func (o *GetLoginRequestTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get login request too many requests response has a 4xx status code
func (o *GetLoginRequestTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get login request too many requests response has a 5xx status code
func (o *GetLoginRequestTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get login request too many requests response a status code equal to that given
func (o *GetLoginRequestTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *GetLoginRequestTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /logins/{login}][%d] getLoginRequestTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetLoginRequestTooManyRequests) String() string {
	return fmt.Sprintf("[GET /logins/{login}][%d] getLoginRequestTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetLoginRequestTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetLoginRequestTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
