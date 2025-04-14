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

// GetLinkedInIDPReader is a Reader for the GetLinkedInIDP structure.
type GetLinkedInIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetLinkedInIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetLinkedInIDPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetLinkedInIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetLinkedInIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetLinkedInIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetLinkedInIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /servers/{wid}/idps/linkedin/{iid}] getLinkedInIDP", response, response.Code())
	}
}

// NewGetLinkedInIDPOK creates a GetLinkedInIDPOK with default headers values
func NewGetLinkedInIDPOK() *GetLinkedInIDPOK {
	return &GetLinkedInIDPOK{}
}

/*
GetLinkedInIDPOK describes a response with status code 200, with default header values.

LinkedInIDP
*/
type GetLinkedInIDPOK struct {
	Payload *models.LinkedInIDP
}

// IsSuccess returns true when this get linked in Id p o k response has a 2xx status code
func (o *GetLinkedInIDPOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get linked in Id p o k response has a 3xx status code
func (o *GetLinkedInIDPOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get linked in Id p o k response has a 4xx status code
func (o *GetLinkedInIDPOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get linked in Id p o k response has a 5xx status code
func (o *GetLinkedInIDPOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get linked in Id p o k response a status code equal to that given
func (o *GetLinkedInIDPOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get linked in Id p o k response
func (o *GetLinkedInIDPOK) Code() int {
	return 200
}

func (o *GetLinkedInIDPOK) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/linkedin/{iid}][%d] getLinkedInIdPOK  %+v", 200, o.Payload)
}

func (o *GetLinkedInIDPOK) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/linkedin/{iid}][%d] getLinkedInIdPOK  %+v", 200, o.Payload)
}

func (o *GetLinkedInIDPOK) GetPayload() *models.LinkedInIDP {
	return o.Payload
}

func (o *GetLinkedInIDPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.LinkedInIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetLinkedInIDPUnauthorized creates a GetLinkedInIDPUnauthorized with default headers values
func NewGetLinkedInIDPUnauthorized() *GetLinkedInIDPUnauthorized {
	return &GetLinkedInIDPUnauthorized{}
}

/*
GetLinkedInIDPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetLinkedInIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get linked in Id p unauthorized response has a 2xx status code
func (o *GetLinkedInIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get linked in Id p unauthorized response has a 3xx status code
func (o *GetLinkedInIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get linked in Id p unauthorized response has a 4xx status code
func (o *GetLinkedInIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get linked in Id p unauthorized response has a 5xx status code
func (o *GetLinkedInIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get linked in Id p unauthorized response a status code equal to that given
func (o *GetLinkedInIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get linked in Id p unauthorized response
func (o *GetLinkedInIDPUnauthorized) Code() int {
	return 401
}

func (o *GetLinkedInIDPUnauthorized) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/linkedin/{iid}][%d] getLinkedInIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *GetLinkedInIDPUnauthorized) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/linkedin/{iid}][%d] getLinkedInIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *GetLinkedInIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetLinkedInIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetLinkedInIDPForbidden creates a GetLinkedInIDPForbidden with default headers values
func NewGetLinkedInIDPForbidden() *GetLinkedInIDPForbidden {
	return &GetLinkedInIDPForbidden{}
}

/*
GetLinkedInIDPForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetLinkedInIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get linked in Id p forbidden response has a 2xx status code
func (o *GetLinkedInIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get linked in Id p forbidden response has a 3xx status code
func (o *GetLinkedInIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get linked in Id p forbidden response has a 4xx status code
func (o *GetLinkedInIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get linked in Id p forbidden response has a 5xx status code
func (o *GetLinkedInIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get linked in Id p forbidden response a status code equal to that given
func (o *GetLinkedInIDPForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get linked in Id p forbidden response
func (o *GetLinkedInIDPForbidden) Code() int {
	return 403
}

func (o *GetLinkedInIDPForbidden) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/linkedin/{iid}][%d] getLinkedInIdPForbidden  %+v", 403, o.Payload)
}

func (o *GetLinkedInIDPForbidden) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/linkedin/{iid}][%d] getLinkedInIdPForbidden  %+v", 403, o.Payload)
}

func (o *GetLinkedInIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetLinkedInIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetLinkedInIDPNotFound creates a GetLinkedInIDPNotFound with default headers values
func NewGetLinkedInIDPNotFound() *GetLinkedInIDPNotFound {
	return &GetLinkedInIDPNotFound{}
}

/*
GetLinkedInIDPNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetLinkedInIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get linked in Id p not found response has a 2xx status code
func (o *GetLinkedInIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get linked in Id p not found response has a 3xx status code
func (o *GetLinkedInIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get linked in Id p not found response has a 4xx status code
func (o *GetLinkedInIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get linked in Id p not found response has a 5xx status code
func (o *GetLinkedInIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get linked in Id p not found response a status code equal to that given
func (o *GetLinkedInIDPNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get linked in Id p not found response
func (o *GetLinkedInIDPNotFound) Code() int {
	return 404
}

func (o *GetLinkedInIDPNotFound) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/linkedin/{iid}][%d] getLinkedInIdPNotFound  %+v", 404, o.Payload)
}

func (o *GetLinkedInIDPNotFound) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/linkedin/{iid}][%d] getLinkedInIdPNotFound  %+v", 404, o.Payload)
}

func (o *GetLinkedInIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetLinkedInIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetLinkedInIDPTooManyRequests creates a GetLinkedInIDPTooManyRequests with default headers values
func NewGetLinkedInIDPTooManyRequests() *GetLinkedInIDPTooManyRequests {
	return &GetLinkedInIDPTooManyRequests{}
}

/*
GetLinkedInIDPTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetLinkedInIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get linked in Id p too many requests response has a 2xx status code
func (o *GetLinkedInIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get linked in Id p too many requests response has a 3xx status code
func (o *GetLinkedInIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get linked in Id p too many requests response has a 4xx status code
func (o *GetLinkedInIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get linked in Id p too many requests response has a 5xx status code
func (o *GetLinkedInIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get linked in Id p too many requests response a status code equal to that given
func (o *GetLinkedInIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get linked in Id p too many requests response
func (o *GetLinkedInIDPTooManyRequests) Code() int {
	return 429
}

func (o *GetLinkedInIDPTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/linkedin/{iid}][%d] getLinkedInIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetLinkedInIDPTooManyRequests) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/linkedin/{iid}][%d] getLinkedInIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetLinkedInIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetLinkedInIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
