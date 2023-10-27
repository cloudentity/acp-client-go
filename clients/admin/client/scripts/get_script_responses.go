// Code generated by go-swagger; DO NOT EDIT.

package scripts

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// GetScriptReader is a Reader for the GetScript structure.
type GetScriptReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetScriptReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetScriptOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetScriptUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetScriptForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetScriptNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetScriptTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /servers/{wid}/scripts/{script}] getScript", response, response.Code())
	}
}

// NewGetScriptOK creates a GetScriptOK with default headers values
func NewGetScriptOK() *GetScriptOK {
	return &GetScriptOK{}
}

/*
GetScriptOK describes a response with status code 200, with default header values.

Script
*/
type GetScriptOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.Script
}

// IsSuccess returns true when this get script o k response has a 2xx status code
func (o *GetScriptOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get script o k response has a 3xx status code
func (o *GetScriptOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get script o k response has a 4xx status code
func (o *GetScriptOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get script o k response has a 5xx status code
func (o *GetScriptOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get script o k response a status code equal to that given
func (o *GetScriptOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get script o k response
func (o *GetScriptOK) Code() int {
	return 200
}

func (o *GetScriptOK) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/scripts/{script}][%d] getScriptOK  %+v", 200, o.Payload)
}

func (o *GetScriptOK) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/scripts/{script}][%d] getScriptOK  %+v", 200, o.Payload)
}

func (o *GetScriptOK) GetPayload() *models.Script {
	return o.Payload
}

func (o *GetScriptOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.Script)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetScriptUnauthorized creates a GetScriptUnauthorized with default headers values
func NewGetScriptUnauthorized() *GetScriptUnauthorized {
	return &GetScriptUnauthorized{}
}

/*
GetScriptUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetScriptUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get script unauthorized response has a 2xx status code
func (o *GetScriptUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get script unauthorized response has a 3xx status code
func (o *GetScriptUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get script unauthorized response has a 4xx status code
func (o *GetScriptUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get script unauthorized response has a 5xx status code
func (o *GetScriptUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get script unauthorized response a status code equal to that given
func (o *GetScriptUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get script unauthorized response
func (o *GetScriptUnauthorized) Code() int {
	return 401
}

func (o *GetScriptUnauthorized) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/scripts/{script}][%d] getScriptUnauthorized  %+v", 401, o.Payload)
}

func (o *GetScriptUnauthorized) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/scripts/{script}][%d] getScriptUnauthorized  %+v", 401, o.Payload)
}

func (o *GetScriptUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetScriptUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetScriptForbidden creates a GetScriptForbidden with default headers values
func NewGetScriptForbidden() *GetScriptForbidden {
	return &GetScriptForbidden{}
}

/*
GetScriptForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetScriptForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get script forbidden response has a 2xx status code
func (o *GetScriptForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get script forbidden response has a 3xx status code
func (o *GetScriptForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get script forbidden response has a 4xx status code
func (o *GetScriptForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get script forbidden response has a 5xx status code
func (o *GetScriptForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get script forbidden response a status code equal to that given
func (o *GetScriptForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get script forbidden response
func (o *GetScriptForbidden) Code() int {
	return 403
}

func (o *GetScriptForbidden) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/scripts/{script}][%d] getScriptForbidden  %+v", 403, o.Payload)
}

func (o *GetScriptForbidden) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/scripts/{script}][%d] getScriptForbidden  %+v", 403, o.Payload)
}

func (o *GetScriptForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetScriptForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetScriptNotFound creates a GetScriptNotFound with default headers values
func NewGetScriptNotFound() *GetScriptNotFound {
	return &GetScriptNotFound{}
}

/*
GetScriptNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetScriptNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get script not found response has a 2xx status code
func (o *GetScriptNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get script not found response has a 3xx status code
func (o *GetScriptNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get script not found response has a 4xx status code
func (o *GetScriptNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get script not found response has a 5xx status code
func (o *GetScriptNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get script not found response a status code equal to that given
func (o *GetScriptNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get script not found response
func (o *GetScriptNotFound) Code() int {
	return 404
}

func (o *GetScriptNotFound) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/scripts/{script}][%d] getScriptNotFound  %+v", 404, o.Payload)
}

func (o *GetScriptNotFound) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/scripts/{script}][%d] getScriptNotFound  %+v", 404, o.Payload)
}

func (o *GetScriptNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetScriptNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetScriptTooManyRequests creates a GetScriptTooManyRequests with default headers values
func NewGetScriptTooManyRequests() *GetScriptTooManyRequests {
	return &GetScriptTooManyRequests{}
}

/*
GetScriptTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetScriptTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get script too many requests response has a 2xx status code
func (o *GetScriptTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get script too many requests response has a 3xx status code
func (o *GetScriptTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get script too many requests response has a 4xx status code
func (o *GetScriptTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get script too many requests response has a 5xx status code
func (o *GetScriptTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get script too many requests response a status code equal to that given
func (o *GetScriptTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get script too many requests response
func (o *GetScriptTooManyRequests) Code() int {
	return 429
}

func (o *GetScriptTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/scripts/{script}][%d] getScriptTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetScriptTooManyRequests) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/scripts/{script}][%d] getScriptTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetScriptTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetScriptTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
