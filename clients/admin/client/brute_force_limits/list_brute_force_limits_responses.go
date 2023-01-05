// Code generated by go-swagger; DO NOT EDIT.

package brute_force_limits

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// ListBruteForceLimitsReader is a Reader for the ListBruteForceLimits structure.
type ListBruteForceLimitsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListBruteForceLimitsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListBruteForceLimitsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListBruteForceLimitsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListBruteForceLimitsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewListBruteForceLimitsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListBruteForceLimitsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewListBruteForceLimitsOK creates a ListBruteForceLimitsOK with default headers values
func NewListBruteForceLimitsOK() *ListBruteForceLimitsOK {
	return &ListBruteForceLimitsOK{}
}

/*
ListBruteForceLimitsOK describes a response with status code 200, with default header values.

BruteForceLimits
*/
type ListBruteForceLimitsOK struct {
	Payload *models.BruteForceLimits
}

// IsSuccess returns true when this list brute force limits o k response has a 2xx status code
func (o *ListBruteForceLimitsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list brute force limits o k response has a 3xx status code
func (o *ListBruteForceLimitsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list brute force limits o k response has a 4xx status code
func (o *ListBruteForceLimitsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list brute force limits o k response has a 5xx status code
func (o *ListBruteForceLimitsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list brute force limits o k response a status code equal to that given
func (o *ListBruteForceLimitsOK) IsCode(code int) bool {
	return code == 200
}

func (o *ListBruteForceLimitsOK) Error() string {
	return fmt.Sprintf("[GET /bruteforce][%d] listBruteForceLimitsOK  %+v", 200, o.Payload)
}

func (o *ListBruteForceLimitsOK) String() string {
	return fmt.Sprintf("[GET /bruteforce][%d] listBruteForceLimitsOK  %+v", 200, o.Payload)
}

func (o *ListBruteForceLimitsOK) GetPayload() *models.BruteForceLimits {
	return o.Payload
}

func (o *ListBruteForceLimitsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.BruteForceLimits)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListBruteForceLimitsUnauthorized creates a ListBruteForceLimitsUnauthorized with default headers values
func NewListBruteForceLimitsUnauthorized() *ListBruteForceLimitsUnauthorized {
	return &ListBruteForceLimitsUnauthorized{}
}

/*
ListBruteForceLimitsUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type ListBruteForceLimitsUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list brute force limits unauthorized response has a 2xx status code
func (o *ListBruteForceLimitsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list brute force limits unauthorized response has a 3xx status code
func (o *ListBruteForceLimitsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list brute force limits unauthorized response has a 4xx status code
func (o *ListBruteForceLimitsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list brute force limits unauthorized response has a 5xx status code
func (o *ListBruteForceLimitsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list brute force limits unauthorized response a status code equal to that given
func (o *ListBruteForceLimitsUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *ListBruteForceLimitsUnauthorized) Error() string {
	return fmt.Sprintf("[GET /bruteforce][%d] listBruteForceLimitsUnauthorized  %+v", 401, o.Payload)
}

func (o *ListBruteForceLimitsUnauthorized) String() string {
	return fmt.Sprintf("[GET /bruteforce][%d] listBruteForceLimitsUnauthorized  %+v", 401, o.Payload)
}

func (o *ListBruteForceLimitsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListBruteForceLimitsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListBruteForceLimitsForbidden creates a ListBruteForceLimitsForbidden with default headers values
func NewListBruteForceLimitsForbidden() *ListBruteForceLimitsForbidden {
	return &ListBruteForceLimitsForbidden{}
}

/*
ListBruteForceLimitsForbidden describes a response with status code 403, with default header values.

HttpError
*/
type ListBruteForceLimitsForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list brute force limits forbidden response has a 2xx status code
func (o *ListBruteForceLimitsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list brute force limits forbidden response has a 3xx status code
func (o *ListBruteForceLimitsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list brute force limits forbidden response has a 4xx status code
func (o *ListBruteForceLimitsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list brute force limits forbidden response has a 5xx status code
func (o *ListBruteForceLimitsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list brute force limits forbidden response a status code equal to that given
func (o *ListBruteForceLimitsForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *ListBruteForceLimitsForbidden) Error() string {
	return fmt.Sprintf("[GET /bruteforce][%d] listBruteForceLimitsForbidden  %+v", 403, o.Payload)
}

func (o *ListBruteForceLimitsForbidden) String() string {
	return fmt.Sprintf("[GET /bruteforce][%d] listBruteForceLimitsForbidden  %+v", 403, o.Payload)
}

func (o *ListBruteForceLimitsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListBruteForceLimitsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListBruteForceLimitsNotFound creates a ListBruteForceLimitsNotFound with default headers values
func NewListBruteForceLimitsNotFound() *ListBruteForceLimitsNotFound {
	return &ListBruteForceLimitsNotFound{}
}

/*
ListBruteForceLimitsNotFound describes a response with status code 404, with default header values.

HttpError
*/
type ListBruteForceLimitsNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this list brute force limits not found response has a 2xx status code
func (o *ListBruteForceLimitsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list brute force limits not found response has a 3xx status code
func (o *ListBruteForceLimitsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list brute force limits not found response has a 4xx status code
func (o *ListBruteForceLimitsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this list brute force limits not found response has a 5xx status code
func (o *ListBruteForceLimitsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this list brute force limits not found response a status code equal to that given
func (o *ListBruteForceLimitsNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *ListBruteForceLimitsNotFound) Error() string {
	return fmt.Sprintf("[GET /bruteforce][%d] listBruteForceLimitsNotFound  %+v", 404, o.Payload)
}

func (o *ListBruteForceLimitsNotFound) String() string {
	return fmt.Sprintf("[GET /bruteforce][%d] listBruteForceLimitsNotFound  %+v", 404, o.Payload)
}

func (o *ListBruteForceLimitsNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListBruteForceLimitsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListBruteForceLimitsTooManyRequests creates a ListBruteForceLimitsTooManyRequests with default headers values
func NewListBruteForceLimitsTooManyRequests() *ListBruteForceLimitsTooManyRequests {
	return &ListBruteForceLimitsTooManyRequests{}
}

/*
ListBruteForceLimitsTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type ListBruteForceLimitsTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list brute force limits too many requests response has a 2xx status code
func (o *ListBruteForceLimitsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list brute force limits too many requests response has a 3xx status code
func (o *ListBruteForceLimitsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list brute force limits too many requests response has a 4xx status code
func (o *ListBruteForceLimitsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list brute force limits too many requests response has a 5xx status code
func (o *ListBruteForceLimitsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list brute force limits too many requests response a status code equal to that given
func (o *ListBruteForceLimitsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *ListBruteForceLimitsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /bruteforce][%d] listBruteForceLimitsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListBruteForceLimitsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /bruteforce][%d] listBruteForceLimitsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListBruteForceLimitsTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListBruteForceLimitsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
