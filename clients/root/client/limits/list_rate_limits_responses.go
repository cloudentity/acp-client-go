// Code generated by go-swagger; DO NOT EDIT.

package limits

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/root/models"
)

// ListRateLimitsReader is a Reader for the ListRateLimits structure.
type ListRateLimitsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListRateLimitsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListRateLimitsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListRateLimitsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListRateLimitsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewListRateLimitsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListRateLimitsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewListRateLimitsOK creates a ListRateLimitsOK with default headers values
func NewListRateLimitsOK() *ListRateLimitsOK {
	return &ListRateLimitsOK{}
}

/*
ListRateLimitsOK describes a response with status code 200, with default header values.

Tenant rate limits
*/
type ListRateLimitsOK struct {
	Payload *models.ListRateLimitsResponse
}

// IsSuccess returns true when this list rate limits o k response has a 2xx status code
func (o *ListRateLimitsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list rate limits o k response has a 3xx status code
func (o *ListRateLimitsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list rate limits o k response has a 4xx status code
func (o *ListRateLimitsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list rate limits o k response has a 5xx status code
func (o *ListRateLimitsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list rate limits o k response a status code equal to that given
func (o *ListRateLimitsOK) IsCode(code int) bool {
	return code == 200
}

func (o *ListRateLimitsOK) Error() string {
	return fmt.Sprintf("[GET /api/admin/tenants/{tid}/rate-limits][%d] listRateLimitsOK  %+v", 200, o.Payload)
}

func (o *ListRateLimitsOK) String() string {
	return fmt.Sprintf("[GET /api/admin/tenants/{tid}/rate-limits][%d] listRateLimitsOK  %+v", 200, o.Payload)
}

func (o *ListRateLimitsOK) GetPayload() *models.ListRateLimitsResponse {
	return o.Payload
}

func (o *ListRateLimitsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ListRateLimitsResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListRateLimitsUnauthorized creates a ListRateLimitsUnauthorized with default headers values
func NewListRateLimitsUnauthorized() *ListRateLimitsUnauthorized {
	return &ListRateLimitsUnauthorized{}
}

/*
ListRateLimitsUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type ListRateLimitsUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list rate limits unauthorized response has a 2xx status code
func (o *ListRateLimitsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list rate limits unauthorized response has a 3xx status code
func (o *ListRateLimitsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list rate limits unauthorized response has a 4xx status code
func (o *ListRateLimitsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list rate limits unauthorized response has a 5xx status code
func (o *ListRateLimitsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list rate limits unauthorized response a status code equal to that given
func (o *ListRateLimitsUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *ListRateLimitsUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/admin/tenants/{tid}/rate-limits][%d] listRateLimitsUnauthorized  %+v", 401, o.Payload)
}

func (o *ListRateLimitsUnauthorized) String() string {
	return fmt.Sprintf("[GET /api/admin/tenants/{tid}/rate-limits][%d] listRateLimitsUnauthorized  %+v", 401, o.Payload)
}

func (o *ListRateLimitsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListRateLimitsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListRateLimitsForbidden creates a ListRateLimitsForbidden with default headers values
func NewListRateLimitsForbidden() *ListRateLimitsForbidden {
	return &ListRateLimitsForbidden{}
}

/*
ListRateLimitsForbidden describes a response with status code 403, with default header values.

HttpError
*/
type ListRateLimitsForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list rate limits forbidden response has a 2xx status code
func (o *ListRateLimitsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list rate limits forbidden response has a 3xx status code
func (o *ListRateLimitsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list rate limits forbidden response has a 4xx status code
func (o *ListRateLimitsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list rate limits forbidden response has a 5xx status code
func (o *ListRateLimitsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list rate limits forbidden response a status code equal to that given
func (o *ListRateLimitsForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *ListRateLimitsForbidden) Error() string {
	return fmt.Sprintf("[GET /api/admin/tenants/{tid}/rate-limits][%d] listRateLimitsForbidden  %+v", 403, o.Payload)
}

func (o *ListRateLimitsForbidden) String() string {
	return fmt.Sprintf("[GET /api/admin/tenants/{tid}/rate-limits][%d] listRateLimitsForbidden  %+v", 403, o.Payload)
}

func (o *ListRateLimitsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListRateLimitsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListRateLimitsNotFound creates a ListRateLimitsNotFound with default headers values
func NewListRateLimitsNotFound() *ListRateLimitsNotFound {
	return &ListRateLimitsNotFound{}
}

/*
ListRateLimitsNotFound describes a response with status code 404, with default header values.

HttpError
*/
type ListRateLimitsNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this list rate limits not found response has a 2xx status code
func (o *ListRateLimitsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list rate limits not found response has a 3xx status code
func (o *ListRateLimitsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list rate limits not found response has a 4xx status code
func (o *ListRateLimitsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this list rate limits not found response has a 5xx status code
func (o *ListRateLimitsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this list rate limits not found response a status code equal to that given
func (o *ListRateLimitsNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *ListRateLimitsNotFound) Error() string {
	return fmt.Sprintf("[GET /api/admin/tenants/{tid}/rate-limits][%d] listRateLimitsNotFound  %+v", 404, o.Payload)
}

func (o *ListRateLimitsNotFound) String() string {
	return fmt.Sprintf("[GET /api/admin/tenants/{tid}/rate-limits][%d] listRateLimitsNotFound  %+v", 404, o.Payload)
}

func (o *ListRateLimitsNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListRateLimitsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListRateLimitsTooManyRequests creates a ListRateLimitsTooManyRequests with default headers values
func NewListRateLimitsTooManyRequests() *ListRateLimitsTooManyRequests {
	return &ListRateLimitsTooManyRequests{}
}

/*
ListRateLimitsTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type ListRateLimitsTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list rate limits too many requests response has a 2xx status code
func (o *ListRateLimitsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list rate limits too many requests response has a 3xx status code
func (o *ListRateLimitsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list rate limits too many requests response has a 4xx status code
func (o *ListRateLimitsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list rate limits too many requests response has a 5xx status code
func (o *ListRateLimitsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list rate limits too many requests response a status code equal to that given
func (o *ListRateLimitsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *ListRateLimitsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /api/admin/tenants/{tid}/rate-limits][%d] listRateLimitsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListRateLimitsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /api/admin/tenants/{tid}/rate-limits][%d] listRateLimitsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListRateLimitsTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListRateLimitsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
