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

// GetStaticIDPReader is a Reader for the GetStaticIDP structure.
type GetStaticIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetStaticIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetStaticIDPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetStaticIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetStaticIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetStaticIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetStaticIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /servers/{wid}/idps/static/{iid}] getStaticIDP", response, response.Code())
	}
}

// NewGetStaticIDPOK creates a GetStaticIDPOK with default headers values
func NewGetStaticIDPOK() *GetStaticIDPOK {
	return &GetStaticIDPOK{}
}

/*
GetStaticIDPOK describes a response with status code 200, with default header values.

StaticIDP
*/
type GetStaticIDPOK struct {
	Payload *models.StaticIDP
}

// IsSuccess returns true when this get static Id p o k response has a 2xx status code
func (o *GetStaticIDPOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get static Id p o k response has a 3xx status code
func (o *GetStaticIDPOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get static Id p o k response has a 4xx status code
func (o *GetStaticIDPOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get static Id p o k response has a 5xx status code
func (o *GetStaticIDPOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get static Id p o k response a status code equal to that given
func (o *GetStaticIDPOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get static Id p o k response
func (o *GetStaticIDPOK) Code() int {
	return 200
}

func (o *GetStaticIDPOK) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/static/{iid}][%d] getStaticIdPOK  %+v", 200, o.Payload)
}

func (o *GetStaticIDPOK) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/static/{iid}][%d] getStaticIdPOK  %+v", 200, o.Payload)
}

func (o *GetStaticIDPOK) GetPayload() *models.StaticIDP {
	return o.Payload
}

func (o *GetStaticIDPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.StaticIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetStaticIDPUnauthorized creates a GetStaticIDPUnauthorized with default headers values
func NewGetStaticIDPUnauthorized() *GetStaticIDPUnauthorized {
	return &GetStaticIDPUnauthorized{}
}

/*
GetStaticIDPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetStaticIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get static Id p unauthorized response has a 2xx status code
func (o *GetStaticIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get static Id p unauthorized response has a 3xx status code
func (o *GetStaticIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get static Id p unauthorized response has a 4xx status code
func (o *GetStaticIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get static Id p unauthorized response has a 5xx status code
func (o *GetStaticIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get static Id p unauthorized response a status code equal to that given
func (o *GetStaticIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get static Id p unauthorized response
func (o *GetStaticIDPUnauthorized) Code() int {
	return 401
}

func (o *GetStaticIDPUnauthorized) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/static/{iid}][%d] getStaticIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *GetStaticIDPUnauthorized) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/static/{iid}][%d] getStaticIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *GetStaticIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetStaticIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetStaticIDPForbidden creates a GetStaticIDPForbidden with default headers values
func NewGetStaticIDPForbidden() *GetStaticIDPForbidden {
	return &GetStaticIDPForbidden{}
}

/*
GetStaticIDPForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetStaticIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get static Id p forbidden response has a 2xx status code
func (o *GetStaticIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get static Id p forbidden response has a 3xx status code
func (o *GetStaticIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get static Id p forbidden response has a 4xx status code
func (o *GetStaticIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get static Id p forbidden response has a 5xx status code
func (o *GetStaticIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get static Id p forbidden response a status code equal to that given
func (o *GetStaticIDPForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get static Id p forbidden response
func (o *GetStaticIDPForbidden) Code() int {
	return 403
}

func (o *GetStaticIDPForbidden) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/static/{iid}][%d] getStaticIdPForbidden  %+v", 403, o.Payload)
}

func (o *GetStaticIDPForbidden) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/static/{iid}][%d] getStaticIdPForbidden  %+v", 403, o.Payload)
}

func (o *GetStaticIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetStaticIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetStaticIDPNotFound creates a GetStaticIDPNotFound with default headers values
func NewGetStaticIDPNotFound() *GetStaticIDPNotFound {
	return &GetStaticIDPNotFound{}
}

/*
GetStaticIDPNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetStaticIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get static Id p not found response has a 2xx status code
func (o *GetStaticIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get static Id p not found response has a 3xx status code
func (o *GetStaticIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get static Id p not found response has a 4xx status code
func (o *GetStaticIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get static Id p not found response has a 5xx status code
func (o *GetStaticIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get static Id p not found response a status code equal to that given
func (o *GetStaticIDPNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get static Id p not found response
func (o *GetStaticIDPNotFound) Code() int {
	return 404
}

func (o *GetStaticIDPNotFound) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/static/{iid}][%d] getStaticIdPNotFound  %+v", 404, o.Payload)
}

func (o *GetStaticIDPNotFound) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/static/{iid}][%d] getStaticIdPNotFound  %+v", 404, o.Payload)
}

func (o *GetStaticIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetStaticIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetStaticIDPTooManyRequests creates a GetStaticIDPTooManyRequests with default headers values
func NewGetStaticIDPTooManyRequests() *GetStaticIDPTooManyRequests {
	return &GetStaticIDPTooManyRequests{}
}

/*
GetStaticIDPTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetStaticIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get static Id p too many requests response has a 2xx status code
func (o *GetStaticIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get static Id p too many requests response has a 3xx status code
func (o *GetStaticIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get static Id p too many requests response has a 4xx status code
func (o *GetStaticIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get static Id p too many requests response has a 5xx status code
func (o *GetStaticIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get static Id p too many requests response a status code equal to that given
func (o *GetStaticIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get static Id p too many requests response
func (o *GetStaticIDPTooManyRequests) Code() int {
	return 429
}

func (o *GetStaticIDPTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/static/{iid}][%d] getStaticIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetStaticIDPTooManyRequests) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/static/{iid}][%d] getStaticIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetStaticIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetStaticIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
