// Code generated by go-swagger; DO NOT EDIT.

package idps

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

// GetAppleIDPReader is a Reader for the GetAppleIDP structure.
type GetAppleIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAppleIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAppleIDPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetAppleIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetAppleIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetAppleIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetAppleIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /servers/{wid}/idps/apple/{iid}] getAppleIDP", response, response.Code())
	}
}

// NewGetAppleIDPOK creates a GetAppleIDPOK with default headers values
func NewGetAppleIDPOK() *GetAppleIDPOK {
	return &GetAppleIDPOK{}
}

/*
GetAppleIDPOK describes a response with status code 200, with default header values.

AppleIDP
*/
type GetAppleIDPOK struct {
	Payload *models.AppleIDP
}

// IsSuccess returns true when this get apple Id p o k response has a 2xx status code
func (o *GetAppleIDPOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get apple Id p o k response has a 3xx status code
func (o *GetAppleIDPOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get apple Id p o k response has a 4xx status code
func (o *GetAppleIDPOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get apple Id p o k response has a 5xx status code
func (o *GetAppleIDPOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get apple Id p o k response a status code equal to that given
func (o *GetAppleIDPOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get apple Id p o k response
func (o *GetAppleIDPOK) Code() int {
	return 200
}

func (o *GetAppleIDPOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/apple/{iid}][%d] getAppleIdPOK %s", 200, payload)
}

func (o *GetAppleIDPOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/apple/{iid}][%d] getAppleIdPOK %s", 200, payload)
}

func (o *GetAppleIDPOK) GetPayload() *models.AppleIDP {
	return o.Payload
}

func (o *GetAppleIDPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.AppleIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAppleIDPUnauthorized creates a GetAppleIDPUnauthorized with default headers values
func NewGetAppleIDPUnauthorized() *GetAppleIDPUnauthorized {
	return &GetAppleIDPUnauthorized{}
}

/*
GetAppleIDPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetAppleIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get apple Id p unauthorized response has a 2xx status code
func (o *GetAppleIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get apple Id p unauthorized response has a 3xx status code
func (o *GetAppleIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get apple Id p unauthorized response has a 4xx status code
func (o *GetAppleIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get apple Id p unauthorized response has a 5xx status code
func (o *GetAppleIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get apple Id p unauthorized response a status code equal to that given
func (o *GetAppleIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get apple Id p unauthorized response
func (o *GetAppleIDPUnauthorized) Code() int {
	return 401
}

func (o *GetAppleIDPUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/apple/{iid}][%d] getAppleIdPUnauthorized %s", 401, payload)
}

func (o *GetAppleIDPUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/apple/{iid}][%d] getAppleIdPUnauthorized %s", 401, payload)
}

func (o *GetAppleIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAppleIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAppleIDPForbidden creates a GetAppleIDPForbidden with default headers values
func NewGetAppleIDPForbidden() *GetAppleIDPForbidden {
	return &GetAppleIDPForbidden{}
}

/*
GetAppleIDPForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetAppleIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get apple Id p forbidden response has a 2xx status code
func (o *GetAppleIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get apple Id p forbidden response has a 3xx status code
func (o *GetAppleIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get apple Id p forbidden response has a 4xx status code
func (o *GetAppleIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get apple Id p forbidden response has a 5xx status code
func (o *GetAppleIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get apple Id p forbidden response a status code equal to that given
func (o *GetAppleIDPForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get apple Id p forbidden response
func (o *GetAppleIDPForbidden) Code() int {
	return 403
}

func (o *GetAppleIDPForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/apple/{iid}][%d] getAppleIdPForbidden %s", 403, payload)
}

func (o *GetAppleIDPForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/apple/{iid}][%d] getAppleIdPForbidden %s", 403, payload)
}

func (o *GetAppleIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAppleIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAppleIDPNotFound creates a GetAppleIDPNotFound with default headers values
func NewGetAppleIDPNotFound() *GetAppleIDPNotFound {
	return &GetAppleIDPNotFound{}
}

/*
GetAppleIDPNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetAppleIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get apple Id p not found response has a 2xx status code
func (o *GetAppleIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get apple Id p not found response has a 3xx status code
func (o *GetAppleIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get apple Id p not found response has a 4xx status code
func (o *GetAppleIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get apple Id p not found response has a 5xx status code
func (o *GetAppleIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get apple Id p not found response a status code equal to that given
func (o *GetAppleIDPNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get apple Id p not found response
func (o *GetAppleIDPNotFound) Code() int {
	return 404
}

func (o *GetAppleIDPNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/apple/{iid}][%d] getAppleIdPNotFound %s", 404, payload)
}

func (o *GetAppleIDPNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/apple/{iid}][%d] getAppleIdPNotFound %s", 404, payload)
}

func (o *GetAppleIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAppleIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAppleIDPTooManyRequests creates a GetAppleIDPTooManyRequests with default headers values
func NewGetAppleIDPTooManyRequests() *GetAppleIDPTooManyRequests {
	return &GetAppleIDPTooManyRequests{}
}

/*
GetAppleIDPTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetAppleIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get apple Id p too many requests response has a 2xx status code
func (o *GetAppleIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get apple Id p too many requests response has a 3xx status code
func (o *GetAppleIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get apple Id p too many requests response has a 4xx status code
func (o *GetAppleIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get apple Id p too many requests response has a 5xx status code
func (o *GetAppleIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get apple Id p too many requests response a status code equal to that given
func (o *GetAppleIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get apple Id p too many requests response
func (o *GetAppleIDPTooManyRequests) Code() int {
	return 429
}

func (o *GetAppleIDPTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/apple/{iid}][%d] getAppleIdPTooManyRequests %s", 429, payload)
}

func (o *GetAppleIDPTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/apple/{iid}][%d] getAppleIdPTooManyRequests %s", 429, payload)
}

func (o *GetAppleIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAppleIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
