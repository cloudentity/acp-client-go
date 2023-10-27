// Code generated by go-swagger; DO NOT EDIT.

package apis

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// GetAPIReader is a Reader for the GetAPI structure.
type GetAPIReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAPIReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAPIOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetAPIUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetAPIForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetAPINotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetAPITooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /apis/{api}] getAPI", response, response.Code())
	}
}

// NewGetAPIOK creates a GetAPIOK with default headers values
func NewGetAPIOK() *GetAPIOK {
	return &GetAPIOK{}
}

/*
GetAPIOK describes a response with status code 200, with default header values.

API
*/
type GetAPIOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.API
}

// IsSuccess returns true when this get Api o k response has a 2xx status code
func (o *GetAPIOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get Api o k response has a 3xx status code
func (o *GetAPIOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api o k response has a 4xx status code
func (o *GetAPIOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get Api o k response has a 5xx status code
func (o *GetAPIOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api o k response a status code equal to that given
func (o *GetAPIOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get Api o k response
func (o *GetAPIOK) Code() int {
	return 200
}

func (o *GetAPIOK) Error() string {
	return fmt.Sprintf("[GET /apis/{api}][%d] getApiOK  %+v", 200, o.Payload)
}

func (o *GetAPIOK) String() string {
	return fmt.Sprintf("[GET /apis/{api}][%d] getApiOK  %+v", 200, o.Payload)
}

func (o *GetAPIOK) GetPayload() *models.API {
	return o.Payload
}

func (o *GetAPIOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.API)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIUnauthorized creates a GetAPIUnauthorized with default headers values
func NewGetAPIUnauthorized() *GetAPIUnauthorized {
	return &GetAPIUnauthorized{}
}

/*
GetAPIUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetAPIUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get Api unauthorized response has a 2xx status code
func (o *GetAPIUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api unauthorized response has a 3xx status code
func (o *GetAPIUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api unauthorized response has a 4xx status code
func (o *GetAPIUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get Api unauthorized response has a 5xx status code
func (o *GetAPIUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api unauthorized response a status code equal to that given
func (o *GetAPIUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get Api unauthorized response
func (o *GetAPIUnauthorized) Code() int {
	return 401
}

func (o *GetAPIUnauthorized) Error() string {
	return fmt.Sprintf("[GET /apis/{api}][%d] getApiUnauthorized  %+v", 401, o.Payload)
}

func (o *GetAPIUnauthorized) String() string {
	return fmt.Sprintf("[GET /apis/{api}][%d] getApiUnauthorized  %+v", 401, o.Payload)
}

func (o *GetAPIUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAPIUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIForbidden creates a GetAPIForbidden with default headers values
func NewGetAPIForbidden() *GetAPIForbidden {
	return &GetAPIForbidden{}
}

/*
GetAPIForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetAPIForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get Api forbidden response has a 2xx status code
func (o *GetAPIForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api forbidden response has a 3xx status code
func (o *GetAPIForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api forbidden response has a 4xx status code
func (o *GetAPIForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get Api forbidden response has a 5xx status code
func (o *GetAPIForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api forbidden response a status code equal to that given
func (o *GetAPIForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get Api forbidden response
func (o *GetAPIForbidden) Code() int {
	return 403
}

func (o *GetAPIForbidden) Error() string {
	return fmt.Sprintf("[GET /apis/{api}][%d] getApiForbidden  %+v", 403, o.Payload)
}

func (o *GetAPIForbidden) String() string {
	return fmt.Sprintf("[GET /apis/{api}][%d] getApiForbidden  %+v", 403, o.Payload)
}

func (o *GetAPIForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAPIForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPINotFound creates a GetAPINotFound with default headers values
func NewGetAPINotFound() *GetAPINotFound {
	return &GetAPINotFound{}
}

/*
GetAPINotFound describes a response with status code 404, with default header values.

Not found
*/
type GetAPINotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get Api not found response has a 2xx status code
func (o *GetAPINotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api not found response has a 3xx status code
func (o *GetAPINotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api not found response has a 4xx status code
func (o *GetAPINotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get Api not found response has a 5xx status code
func (o *GetAPINotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api not found response a status code equal to that given
func (o *GetAPINotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get Api not found response
func (o *GetAPINotFound) Code() int {
	return 404
}

func (o *GetAPINotFound) Error() string {
	return fmt.Sprintf("[GET /apis/{api}][%d] getApiNotFound  %+v", 404, o.Payload)
}

func (o *GetAPINotFound) String() string {
	return fmt.Sprintf("[GET /apis/{api}][%d] getApiNotFound  %+v", 404, o.Payload)
}

func (o *GetAPINotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAPINotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPITooManyRequests creates a GetAPITooManyRequests with default headers values
func NewGetAPITooManyRequests() *GetAPITooManyRequests {
	return &GetAPITooManyRequests{}
}

/*
GetAPITooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetAPITooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get Api too many requests response has a 2xx status code
func (o *GetAPITooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api too many requests response has a 3xx status code
func (o *GetAPITooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api too many requests response has a 4xx status code
func (o *GetAPITooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get Api too many requests response has a 5xx status code
func (o *GetAPITooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api too many requests response a status code equal to that given
func (o *GetAPITooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get Api too many requests response
func (o *GetAPITooManyRequests) Code() int {
	return 429
}

func (o *GetAPITooManyRequests) Error() string {
	return fmt.Sprintf("[GET /apis/{api}][%d] getApiTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetAPITooManyRequests) String() string {
	return fmt.Sprintf("[GET /apis/{api}][%d] getApiTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetAPITooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAPITooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
