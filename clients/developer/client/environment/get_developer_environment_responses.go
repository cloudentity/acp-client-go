// Code generated by go-swagger; DO NOT EDIT.

package environment

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/developer/models"
)

// GetDeveloperEnvironmentReader is a Reader for the GetDeveloperEnvironment structure.
type GetDeveloperEnvironmentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetDeveloperEnvironmentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetDeveloperEnvironmentOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetDeveloperEnvironmentUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetDeveloperEnvironmentForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetDeveloperEnvironmentTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetDeveloperEnvironmentOK creates a GetDeveloperEnvironmentOK with default headers values
func NewGetDeveloperEnvironmentOK() *GetDeveloperEnvironmentOK {
	return &GetDeveloperEnvironmentOK{}
}

/*
GetDeveloperEnvironmentOK describes a response with status code 200, with default header values.

Developer environment
*/
type GetDeveloperEnvironmentOK struct {
	Payload *models.DeveloperEnvironment
}

// IsSuccess returns true when this get developer environment o k response has a 2xx status code
func (o *GetDeveloperEnvironmentOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get developer environment o k response has a 3xx status code
func (o *GetDeveloperEnvironmentOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get developer environment o k response has a 4xx status code
func (o *GetDeveloperEnvironmentOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get developer environment o k response has a 5xx status code
func (o *GetDeveloperEnvironmentOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get developer environment o k response a status code equal to that given
func (o *GetDeveloperEnvironmentOK) IsCode(code int) bool {
	return code == 200
}

func (o *GetDeveloperEnvironmentOK) Error() string {
	return fmt.Sprintf("[GET /environment][%d] getDeveloperEnvironmentOK  %+v", 200, o.Payload)
}

func (o *GetDeveloperEnvironmentOK) String() string {
	return fmt.Sprintf("[GET /environment][%d] getDeveloperEnvironmentOK  %+v", 200, o.Payload)
}

func (o *GetDeveloperEnvironmentOK) GetPayload() *models.DeveloperEnvironment {
	return o.Payload
}

func (o *GetDeveloperEnvironmentOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.DeveloperEnvironment)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDeveloperEnvironmentUnauthorized creates a GetDeveloperEnvironmentUnauthorized with default headers values
func NewGetDeveloperEnvironmentUnauthorized() *GetDeveloperEnvironmentUnauthorized {
	return &GetDeveloperEnvironmentUnauthorized{}
}

/*
GetDeveloperEnvironmentUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type GetDeveloperEnvironmentUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get developer environment unauthorized response has a 2xx status code
func (o *GetDeveloperEnvironmentUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get developer environment unauthorized response has a 3xx status code
func (o *GetDeveloperEnvironmentUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get developer environment unauthorized response has a 4xx status code
func (o *GetDeveloperEnvironmentUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get developer environment unauthorized response has a 5xx status code
func (o *GetDeveloperEnvironmentUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get developer environment unauthorized response a status code equal to that given
func (o *GetDeveloperEnvironmentUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *GetDeveloperEnvironmentUnauthorized) Error() string {
	return fmt.Sprintf("[GET /environment][%d] getDeveloperEnvironmentUnauthorized  %+v", 401, o.Payload)
}

func (o *GetDeveloperEnvironmentUnauthorized) String() string {
	return fmt.Sprintf("[GET /environment][%d] getDeveloperEnvironmentUnauthorized  %+v", 401, o.Payload)
}

func (o *GetDeveloperEnvironmentUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetDeveloperEnvironmentUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDeveloperEnvironmentForbidden creates a GetDeveloperEnvironmentForbidden with default headers values
func NewGetDeveloperEnvironmentForbidden() *GetDeveloperEnvironmentForbidden {
	return &GetDeveloperEnvironmentForbidden{}
}

/*
GetDeveloperEnvironmentForbidden describes a response with status code 403, with default header values.

HttpError
*/
type GetDeveloperEnvironmentForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get developer environment forbidden response has a 2xx status code
func (o *GetDeveloperEnvironmentForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get developer environment forbidden response has a 3xx status code
func (o *GetDeveloperEnvironmentForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get developer environment forbidden response has a 4xx status code
func (o *GetDeveloperEnvironmentForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get developer environment forbidden response has a 5xx status code
func (o *GetDeveloperEnvironmentForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get developer environment forbidden response a status code equal to that given
func (o *GetDeveloperEnvironmentForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *GetDeveloperEnvironmentForbidden) Error() string {
	return fmt.Sprintf("[GET /environment][%d] getDeveloperEnvironmentForbidden  %+v", 403, o.Payload)
}

func (o *GetDeveloperEnvironmentForbidden) String() string {
	return fmt.Sprintf("[GET /environment][%d] getDeveloperEnvironmentForbidden  %+v", 403, o.Payload)
}

func (o *GetDeveloperEnvironmentForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetDeveloperEnvironmentForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDeveloperEnvironmentTooManyRequests creates a GetDeveloperEnvironmentTooManyRequests with default headers values
func NewGetDeveloperEnvironmentTooManyRequests() *GetDeveloperEnvironmentTooManyRequests {
	return &GetDeveloperEnvironmentTooManyRequests{}
}

/*
GetDeveloperEnvironmentTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type GetDeveloperEnvironmentTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get developer environment too many requests response has a 2xx status code
func (o *GetDeveloperEnvironmentTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get developer environment too many requests response has a 3xx status code
func (o *GetDeveloperEnvironmentTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get developer environment too many requests response has a 4xx status code
func (o *GetDeveloperEnvironmentTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get developer environment too many requests response has a 5xx status code
func (o *GetDeveloperEnvironmentTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get developer environment too many requests response a status code equal to that given
func (o *GetDeveloperEnvironmentTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *GetDeveloperEnvironmentTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /environment][%d] getDeveloperEnvironmentTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetDeveloperEnvironmentTooManyRequests) String() string {
	return fmt.Sprintf("[GET /environment][%d] getDeveloperEnvironmentTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetDeveloperEnvironmentTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetDeveloperEnvironmentTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
