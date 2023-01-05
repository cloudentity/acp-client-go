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

// ListPoliciesReader is a Reader for the ListPolicies structure.
type ListPoliciesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListPoliciesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListPoliciesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewListPoliciesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewListPoliciesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListPoliciesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListPoliciesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewListPoliciesOK creates a ListPoliciesOK with default headers values
func NewListPoliciesOK() *ListPoliciesOK {
	return &ListPoliciesOK{}
}

/*
ListPoliciesOK describes a response with status code 200, with default header values.

Policies
*/
type ListPoliciesOK struct {
	Payload *models.Policies
}

// IsSuccess returns true when this list policies o k response has a 2xx status code
func (o *ListPoliciesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list policies o k response has a 3xx status code
func (o *ListPoliciesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list policies o k response has a 4xx status code
func (o *ListPoliciesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list policies o k response has a 5xx status code
func (o *ListPoliciesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list policies o k response a status code equal to that given
func (o *ListPoliciesOK) IsCode(code int) bool {
	return code == 200
}

func (o *ListPoliciesOK) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/policies][%d] listPoliciesOK  %+v", 200, o.Payload)
}

func (o *ListPoliciesOK) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/policies][%d] listPoliciesOK  %+v", 200, o.Payload)
}

func (o *ListPoliciesOK) GetPayload() *models.Policies {
	return o.Payload
}

func (o *ListPoliciesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Policies)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListPoliciesBadRequest creates a ListPoliciesBadRequest with default headers values
func NewListPoliciesBadRequest() *ListPoliciesBadRequest {
	return &ListPoliciesBadRequest{}
}

/*
ListPoliciesBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type ListPoliciesBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this list policies bad request response has a 2xx status code
func (o *ListPoliciesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list policies bad request response has a 3xx status code
func (o *ListPoliciesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list policies bad request response has a 4xx status code
func (o *ListPoliciesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this list policies bad request response has a 5xx status code
func (o *ListPoliciesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this list policies bad request response a status code equal to that given
func (o *ListPoliciesBadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *ListPoliciesBadRequest) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/policies][%d] listPoliciesBadRequest  %+v", 400, o.Payload)
}

func (o *ListPoliciesBadRequest) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/policies][%d] listPoliciesBadRequest  %+v", 400, o.Payload)
}

func (o *ListPoliciesBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListPoliciesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListPoliciesUnauthorized creates a ListPoliciesUnauthorized with default headers values
func NewListPoliciesUnauthorized() *ListPoliciesUnauthorized {
	return &ListPoliciesUnauthorized{}
}

/*
ListPoliciesUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type ListPoliciesUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list policies unauthorized response has a 2xx status code
func (o *ListPoliciesUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list policies unauthorized response has a 3xx status code
func (o *ListPoliciesUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list policies unauthorized response has a 4xx status code
func (o *ListPoliciesUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list policies unauthorized response has a 5xx status code
func (o *ListPoliciesUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list policies unauthorized response a status code equal to that given
func (o *ListPoliciesUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *ListPoliciesUnauthorized) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/policies][%d] listPoliciesUnauthorized  %+v", 401, o.Payload)
}

func (o *ListPoliciesUnauthorized) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/policies][%d] listPoliciesUnauthorized  %+v", 401, o.Payload)
}

func (o *ListPoliciesUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListPoliciesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListPoliciesForbidden creates a ListPoliciesForbidden with default headers values
func NewListPoliciesForbidden() *ListPoliciesForbidden {
	return &ListPoliciesForbidden{}
}

/*
ListPoliciesForbidden describes a response with status code 403, with default header values.

HttpError
*/
type ListPoliciesForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list policies forbidden response has a 2xx status code
func (o *ListPoliciesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list policies forbidden response has a 3xx status code
func (o *ListPoliciesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list policies forbidden response has a 4xx status code
func (o *ListPoliciesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list policies forbidden response has a 5xx status code
func (o *ListPoliciesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list policies forbidden response a status code equal to that given
func (o *ListPoliciesForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *ListPoliciesForbidden) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/policies][%d] listPoliciesForbidden  %+v", 403, o.Payload)
}

func (o *ListPoliciesForbidden) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/policies][%d] listPoliciesForbidden  %+v", 403, o.Payload)
}

func (o *ListPoliciesForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListPoliciesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListPoliciesTooManyRequests creates a ListPoliciesTooManyRequests with default headers values
func NewListPoliciesTooManyRequests() *ListPoliciesTooManyRequests {
	return &ListPoliciesTooManyRequests{}
}

/*
ListPoliciesTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type ListPoliciesTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list policies too many requests response has a 2xx status code
func (o *ListPoliciesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list policies too many requests response has a 3xx status code
func (o *ListPoliciesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list policies too many requests response has a 4xx status code
func (o *ListPoliciesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list policies too many requests response has a 5xx status code
func (o *ListPoliciesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list policies too many requests response a status code equal to that given
func (o *ListPoliciesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *ListPoliciesTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/policies][%d] listPoliciesTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListPoliciesTooManyRequests) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/policies][%d] listPoliciesTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListPoliciesTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListPoliciesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
