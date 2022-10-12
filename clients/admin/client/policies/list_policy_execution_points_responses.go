// Code generated by go-swagger; DO NOT EDIT.

package policies

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// ListPolicyExecutionPointsReader is a Reader for the ListPolicyExecutionPoints structure.
type ListPolicyExecutionPointsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListPolicyExecutionPointsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListPolicyExecutionPointsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListPolicyExecutionPointsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListPolicyExecutionPointsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListPolicyExecutionPointsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewListPolicyExecutionPointsOK creates a ListPolicyExecutionPointsOK with default headers values
func NewListPolicyExecutionPointsOK() *ListPolicyExecutionPointsOK {
	return &ListPolicyExecutionPointsOK{}
}

/*
ListPolicyExecutionPointsOK describes a response with status code 200, with default header values.

Policy execution points
*/
type ListPolicyExecutionPointsOK struct {
	Payload *models.PolicyExecutionPoints
}

// IsSuccess returns true when this list policy execution points o k response has a 2xx status code
func (o *ListPolicyExecutionPointsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list policy execution points o k response has a 3xx status code
func (o *ListPolicyExecutionPointsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list policy execution points o k response has a 4xx status code
func (o *ListPolicyExecutionPointsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list policy execution points o k response has a 5xx status code
func (o *ListPolicyExecutionPointsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list policy execution points o k response a status code equal to that given
func (o *ListPolicyExecutionPointsOK) IsCode(code int) bool {
	return code == 200
}

func (o *ListPolicyExecutionPointsOK) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/policy-execution-points][%d] listPolicyExecutionPointsOK  %+v", 200, o.Payload)
}

func (o *ListPolicyExecutionPointsOK) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/policy-execution-points][%d] listPolicyExecutionPointsOK  %+v", 200, o.Payload)
}

func (o *ListPolicyExecutionPointsOK) GetPayload() *models.PolicyExecutionPoints {
	return o.Payload
}

func (o *ListPolicyExecutionPointsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PolicyExecutionPoints)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListPolicyExecutionPointsUnauthorized creates a ListPolicyExecutionPointsUnauthorized with default headers values
func NewListPolicyExecutionPointsUnauthorized() *ListPolicyExecutionPointsUnauthorized {
	return &ListPolicyExecutionPointsUnauthorized{}
}

/*
ListPolicyExecutionPointsUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type ListPolicyExecutionPointsUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list policy execution points unauthorized response has a 2xx status code
func (o *ListPolicyExecutionPointsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list policy execution points unauthorized response has a 3xx status code
func (o *ListPolicyExecutionPointsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list policy execution points unauthorized response has a 4xx status code
func (o *ListPolicyExecutionPointsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list policy execution points unauthorized response has a 5xx status code
func (o *ListPolicyExecutionPointsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list policy execution points unauthorized response a status code equal to that given
func (o *ListPolicyExecutionPointsUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *ListPolicyExecutionPointsUnauthorized) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/policy-execution-points][%d] listPolicyExecutionPointsUnauthorized  %+v", 401, o.Payload)
}

func (o *ListPolicyExecutionPointsUnauthorized) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/policy-execution-points][%d] listPolicyExecutionPointsUnauthorized  %+v", 401, o.Payload)
}

func (o *ListPolicyExecutionPointsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListPolicyExecutionPointsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListPolicyExecutionPointsForbidden creates a ListPolicyExecutionPointsForbidden with default headers values
func NewListPolicyExecutionPointsForbidden() *ListPolicyExecutionPointsForbidden {
	return &ListPolicyExecutionPointsForbidden{}
}

/*
ListPolicyExecutionPointsForbidden describes a response with status code 403, with default header values.

HttpError
*/
type ListPolicyExecutionPointsForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list policy execution points forbidden response has a 2xx status code
func (o *ListPolicyExecutionPointsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list policy execution points forbidden response has a 3xx status code
func (o *ListPolicyExecutionPointsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list policy execution points forbidden response has a 4xx status code
func (o *ListPolicyExecutionPointsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list policy execution points forbidden response has a 5xx status code
func (o *ListPolicyExecutionPointsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list policy execution points forbidden response a status code equal to that given
func (o *ListPolicyExecutionPointsForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *ListPolicyExecutionPointsForbidden) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/policy-execution-points][%d] listPolicyExecutionPointsForbidden  %+v", 403, o.Payload)
}

func (o *ListPolicyExecutionPointsForbidden) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/policy-execution-points][%d] listPolicyExecutionPointsForbidden  %+v", 403, o.Payload)
}

func (o *ListPolicyExecutionPointsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListPolicyExecutionPointsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListPolicyExecutionPointsTooManyRequests creates a ListPolicyExecutionPointsTooManyRequests with default headers values
func NewListPolicyExecutionPointsTooManyRequests() *ListPolicyExecutionPointsTooManyRequests {
	return &ListPolicyExecutionPointsTooManyRequests{}
}

/*
ListPolicyExecutionPointsTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type ListPolicyExecutionPointsTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list policy execution points too many requests response has a 2xx status code
func (o *ListPolicyExecutionPointsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list policy execution points too many requests response has a 3xx status code
func (o *ListPolicyExecutionPointsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list policy execution points too many requests response has a 4xx status code
func (o *ListPolicyExecutionPointsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list policy execution points too many requests response has a 5xx status code
func (o *ListPolicyExecutionPointsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list policy execution points too many requests response a status code equal to that given
func (o *ListPolicyExecutionPointsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *ListPolicyExecutionPointsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/policy-execution-points][%d] listPolicyExecutionPointsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListPolicyExecutionPointsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/policy-execution-points][%d] listPolicyExecutionPointsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListPolicyExecutionPointsTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListPolicyExecutionPointsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
