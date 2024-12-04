// Code generated by go-swagger; DO NOT EDIT.

package a_c_rs

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// ListACRsReader is a Reader for the ListACRs structure.
type ListACRsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListACRsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListACRsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListACRsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListACRsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListACRsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /servers/{wid}/acrs] listACRs", response, response.Code())
	}
}

// NewListACRsOK creates a ListACRsOK with default headers values
func NewListACRsOK() *ListACRsOK {
	return &ListACRsOK{}
}

/*
ListACRsOK describes a response with status code 200, with default header values.

ACRs
*/
type ListACRsOK struct {
	Payload *models.ACRs
}

// IsSuccess returns true when this list a c rs o k response has a 2xx status code
func (o *ListACRsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list a c rs o k response has a 3xx status code
func (o *ListACRsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list a c rs o k response has a 4xx status code
func (o *ListACRsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list a c rs o k response has a 5xx status code
func (o *ListACRsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list a c rs o k response a status code equal to that given
func (o *ListACRsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the list a c rs o k response
func (o *ListACRsOK) Code() int {
	return 200
}

func (o *ListACRsOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/acrs][%d] listACRsOK %s", 200, payload)
}

func (o *ListACRsOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/acrs][%d] listACRsOK %s", 200, payload)
}

func (o *ListACRsOK) GetPayload() *models.ACRs {
	return o.Payload
}

func (o *ListACRsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ACRs)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListACRsUnauthorized creates a ListACRsUnauthorized with default headers values
func NewListACRsUnauthorized() *ListACRsUnauthorized {
	return &ListACRsUnauthorized{}
}

/*
ListACRsUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type ListACRsUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list a c rs unauthorized response has a 2xx status code
func (o *ListACRsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list a c rs unauthorized response has a 3xx status code
func (o *ListACRsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list a c rs unauthorized response has a 4xx status code
func (o *ListACRsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list a c rs unauthorized response has a 5xx status code
func (o *ListACRsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list a c rs unauthorized response a status code equal to that given
func (o *ListACRsUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the list a c rs unauthorized response
func (o *ListACRsUnauthorized) Code() int {
	return 401
}

func (o *ListACRsUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/acrs][%d] listACRsUnauthorized %s", 401, payload)
}

func (o *ListACRsUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/acrs][%d] listACRsUnauthorized %s", 401, payload)
}

func (o *ListACRsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListACRsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListACRsForbidden creates a ListACRsForbidden with default headers values
func NewListACRsForbidden() *ListACRsForbidden {
	return &ListACRsForbidden{}
}

/*
ListACRsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ListACRsForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list a c rs forbidden response has a 2xx status code
func (o *ListACRsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list a c rs forbidden response has a 3xx status code
func (o *ListACRsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list a c rs forbidden response has a 4xx status code
func (o *ListACRsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list a c rs forbidden response has a 5xx status code
func (o *ListACRsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list a c rs forbidden response a status code equal to that given
func (o *ListACRsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the list a c rs forbidden response
func (o *ListACRsForbidden) Code() int {
	return 403
}

func (o *ListACRsForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/acrs][%d] listACRsForbidden %s", 403, payload)
}

func (o *ListACRsForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/acrs][%d] listACRsForbidden %s", 403, payload)
}

func (o *ListACRsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListACRsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListACRsTooManyRequests creates a ListACRsTooManyRequests with default headers values
func NewListACRsTooManyRequests() *ListACRsTooManyRequests {
	return &ListACRsTooManyRequests{}
}

/*
ListACRsTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type ListACRsTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list a c rs too many requests response has a 2xx status code
func (o *ListACRsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list a c rs too many requests response has a 3xx status code
func (o *ListACRsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list a c rs too many requests response has a 4xx status code
func (o *ListACRsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list a c rs too many requests response has a 5xx status code
func (o *ListACRsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list a c rs too many requests response a status code equal to that given
func (o *ListACRsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the list a c rs too many requests response
func (o *ListACRsTooManyRequests) Code() int {
	return 429
}

func (o *ListACRsTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/acrs][%d] listACRsTooManyRequests %s", 429, payload)
}

func (o *ListACRsTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/acrs][%d] listACRsTooManyRequests %s", 429, payload)
}

func (o *ListACRsTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListACRsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
