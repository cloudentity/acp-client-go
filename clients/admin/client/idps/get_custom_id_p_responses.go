// Code generated by go-swagger; DO NOT EDIT.

package idps

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// GetCustomIDPReader is a Reader for the GetCustomIDP structure.
type GetCustomIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetCustomIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetCustomIDPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetCustomIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetCustomIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetCustomIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetCustomIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /servers/{wid}/idps/custom/{iid}] getCustomIDP", response, response.Code())
	}
}

// NewGetCustomIDPOK creates a GetCustomIDPOK with default headers values
func NewGetCustomIDPOK() *GetCustomIDPOK {
	return &GetCustomIDPOK{}
}

/*
GetCustomIDPOK describes a response with status code 200, with default header values.

CustomIDP
*/
type GetCustomIDPOK struct {
	Payload *models.CustomIDP
}

// IsSuccess returns true when this get custom Id p o k response has a 2xx status code
func (o *GetCustomIDPOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get custom Id p o k response has a 3xx status code
func (o *GetCustomIDPOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get custom Id p o k response has a 4xx status code
func (o *GetCustomIDPOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get custom Id p o k response has a 5xx status code
func (o *GetCustomIDPOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get custom Id p o k response a status code equal to that given
func (o *GetCustomIDPOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get custom Id p o k response
func (o *GetCustomIDPOK) Code() int {
	return 200
}

func (o *GetCustomIDPOK) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/custom/{iid}][%d] getCustomIdPOK  %+v", 200, o.Payload)
}

func (o *GetCustomIDPOK) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/custom/{iid}][%d] getCustomIdPOK  %+v", 200, o.Payload)
}

func (o *GetCustomIDPOK) GetPayload() *models.CustomIDP {
	return o.Payload
}

func (o *GetCustomIDPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.CustomIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetCustomIDPUnauthorized creates a GetCustomIDPUnauthorized with default headers values
func NewGetCustomIDPUnauthorized() *GetCustomIDPUnauthorized {
	return &GetCustomIDPUnauthorized{}
}

/*
GetCustomIDPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetCustomIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get custom Id p unauthorized response has a 2xx status code
func (o *GetCustomIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get custom Id p unauthorized response has a 3xx status code
func (o *GetCustomIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get custom Id p unauthorized response has a 4xx status code
func (o *GetCustomIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get custom Id p unauthorized response has a 5xx status code
func (o *GetCustomIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get custom Id p unauthorized response a status code equal to that given
func (o *GetCustomIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get custom Id p unauthorized response
func (o *GetCustomIDPUnauthorized) Code() int {
	return 401
}

func (o *GetCustomIDPUnauthorized) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/custom/{iid}][%d] getCustomIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *GetCustomIDPUnauthorized) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/custom/{iid}][%d] getCustomIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *GetCustomIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetCustomIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetCustomIDPForbidden creates a GetCustomIDPForbidden with default headers values
func NewGetCustomIDPForbidden() *GetCustomIDPForbidden {
	return &GetCustomIDPForbidden{}
}

/*
GetCustomIDPForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetCustomIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get custom Id p forbidden response has a 2xx status code
func (o *GetCustomIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get custom Id p forbidden response has a 3xx status code
func (o *GetCustomIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get custom Id p forbidden response has a 4xx status code
func (o *GetCustomIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get custom Id p forbidden response has a 5xx status code
func (o *GetCustomIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get custom Id p forbidden response a status code equal to that given
func (o *GetCustomIDPForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get custom Id p forbidden response
func (o *GetCustomIDPForbidden) Code() int {
	return 403
}

func (o *GetCustomIDPForbidden) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/custom/{iid}][%d] getCustomIdPForbidden  %+v", 403, o.Payload)
}

func (o *GetCustomIDPForbidden) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/custom/{iid}][%d] getCustomIdPForbidden  %+v", 403, o.Payload)
}

func (o *GetCustomIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetCustomIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetCustomIDPNotFound creates a GetCustomIDPNotFound with default headers values
func NewGetCustomIDPNotFound() *GetCustomIDPNotFound {
	return &GetCustomIDPNotFound{}
}

/*
GetCustomIDPNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetCustomIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get custom Id p not found response has a 2xx status code
func (o *GetCustomIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get custom Id p not found response has a 3xx status code
func (o *GetCustomIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get custom Id p not found response has a 4xx status code
func (o *GetCustomIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get custom Id p not found response has a 5xx status code
func (o *GetCustomIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get custom Id p not found response a status code equal to that given
func (o *GetCustomIDPNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get custom Id p not found response
func (o *GetCustomIDPNotFound) Code() int {
	return 404
}

func (o *GetCustomIDPNotFound) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/custom/{iid}][%d] getCustomIdPNotFound  %+v", 404, o.Payload)
}

func (o *GetCustomIDPNotFound) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/custom/{iid}][%d] getCustomIdPNotFound  %+v", 404, o.Payload)
}

func (o *GetCustomIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetCustomIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetCustomIDPTooManyRequests creates a GetCustomIDPTooManyRequests with default headers values
func NewGetCustomIDPTooManyRequests() *GetCustomIDPTooManyRequests {
	return &GetCustomIDPTooManyRequests{}
}

/*
GetCustomIDPTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetCustomIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get custom Id p too many requests response has a 2xx status code
func (o *GetCustomIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get custom Id p too many requests response has a 3xx status code
func (o *GetCustomIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get custom Id p too many requests response has a 4xx status code
func (o *GetCustomIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get custom Id p too many requests response has a 5xx status code
func (o *GetCustomIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get custom Id p too many requests response a status code equal to that given
func (o *GetCustomIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get custom Id p too many requests response
func (o *GetCustomIDPTooManyRequests) Code() int {
	return 429
}

func (o *GetCustomIDPTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/custom/{iid}][%d] getCustomIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetCustomIDPTooManyRequests) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/custom/{iid}][%d] getCustomIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetCustomIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetCustomIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
