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

// GetIdentityPoolIDPReader is a Reader for the GetIdentityPoolIDP structure.
type GetIdentityPoolIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetIdentityPoolIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetIdentityPoolIDPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetIdentityPoolIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetIdentityPoolIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetIdentityPoolIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetIdentityPoolIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /servers/{wid}/idps/identity_pool/{iid}] getIdentityPoolIDP", response, response.Code())
	}
}

// NewGetIdentityPoolIDPOK creates a GetIdentityPoolIDPOK with default headers values
func NewGetIdentityPoolIDPOK() *GetIdentityPoolIDPOK {
	return &GetIdentityPoolIDPOK{}
}

/*
GetIdentityPoolIDPOK describes a response with status code 200, with default header values.

IdentityPoolIDP
*/
type GetIdentityPoolIDPOK struct {
	Payload *models.IdentityPoolIDP
}

// IsSuccess returns true when this get identity pool Id p o k response has a 2xx status code
func (o *GetIdentityPoolIDPOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get identity pool Id p o k response has a 3xx status code
func (o *GetIdentityPoolIDPOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get identity pool Id p o k response has a 4xx status code
func (o *GetIdentityPoolIDPOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get identity pool Id p o k response has a 5xx status code
func (o *GetIdentityPoolIDPOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get identity pool Id p o k response a status code equal to that given
func (o *GetIdentityPoolIDPOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get identity pool Id p o k response
func (o *GetIdentityPoolIDPOK) Code() int {
	return 200
}

func (o *GetIdentityPoolIDPOK) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/identity_pool/{iid}][%d] getIdentityPoolIdPOK  %+v", 200, o.Payload)
}

func (o *GetIdentityPoolIDPOK) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/identity_pool/{iid}][%d] getIdentityPoolIdPOK  %+v", 200, o.Payload)
}

func (o *GetIdentityPoolIDPOK) GetPayload() *models.IdentityPoolIDP {
	return o.Payload
}

func (o *GetIdentityPoolIDPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.IdentityPoolIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetIdentityPoolIDPUnauthorized creates a GetIdentityPoolIDPUnauthorized with default headers values
func NewGetIdentityPoolIDPUnauthorized() *GetIdentityPoolIDPUnauthorized {
	return &GetIdentityPoolIDPUnauthorized{}
}

/*
GetIdentityPoolIDPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetIdentityPoolIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get identity pool Id p unauthorized response has a 2xx status code
func (o *GetIdentityPoolIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get identity pool Id p unauthorized response has a 3xx status code
func (o *GetIdentityPoolIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get identity pool Id p unauthorized response has a 4xx status code
func (o *GetIdentityPoolIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get identity pool Id p unauthorized response has a 5xx status code
func (o *GetIdentityPoolIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get identity pool Id p unauthorized response a status code equal to that given
func (o *GetIdentityPoolIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get identity pool Id p unauthorized response
func (o *GetIdentityPoolIDPUnauthorized) Code() int {
	return 401
}

func (o *GetIdentityPoolIDPUnauthorized) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/identity_pool/{iid}][%d] getIdentityPoolIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *GetIdentityPoolIDPUnauthorized) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/identity_pool/{iid}][%d] getIdentityPoolIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *GetIdentityPoolIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetIdentityPoolIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetIdentityPoolIDPForbidden creates a GetIdentityPoolIDPForbidden with default headers values
func NewGetIdentityPoolIDPForbidden() *GetIdentityPoolIDPForbidden {
	return &GetIdentityPoolIDPForbidden{}
}

/*
GetIdentityPoolIDPForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetIdentityPoolIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get identity pool Id p forbidden response has a 2xx status code
func (o *GetIdentityPoolIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get identity pool Id p forbidden response has a 3xx status code
func (o *GetIdentityPoolIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get identity pool Id p forbidden response has a 4xx status code
func (o *GetIdentityPoolIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get identity pool Id p forbidden response has a 5xx status code
func (o *GetIdentityPoolIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get identity pool Id p forbidden response a status code equal to that given
func (o *GetIdentityPoolIDPForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get identity pool Id p forbidden response
func (o *GetIdentityPoolIDPForbidden) Code() int {
	return 403
}

func (o *GetIdentityPoolIDPForbidden) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/identity_pool/{iid}][%d] getIdentityPoolIdPForbidden  %+v", 403, o.Payload)
}

func (o *GetIdentityPoolIDPForbidden) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/identity_pool/{iid}][%d] getIdentityPoolIdPForbidden  %+v", 403, o.Payload)
}

func (o *GetIdentityPoolIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetIdentityPoolIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetIdentityPoolIDPNotFound creates a GetIdentityPoolIDPNotFound with default headers values
func NewGetIdentityPoolIDPNotFound() *GetIdentityPoolIDPNotFound {
	return &GetIdentityPoolIDPNotFound{}
}

/*
GetIdentityPoolIDPNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetIdentityPoolIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get identity pool Id p not found response has a 2xx status code
func (o *GetIdentityPoolIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get identity pool Id p not found response has a 3xx status code
func (o *GetIdentityPoolIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get identity pool Id p not found response has a 4xx status code
func (o *GetIdentityPoolIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get identity pool Id p not found response has a 5xx status code
func (o *GetIdentityPoolIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get identity pool Id p not found response a status code equal to that given
func (o *GetIdentityPoolIDPNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get identity pool Id p not found response
func (o *GetIdentityPoolIDPNotFound) Code() int {
	return 404
}

func (o *GetIdentityPoolIDPNotFound) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/identity_pool/{iid}][%d] getIdentityPoolIdPNotFound  %+v", 404, o.Payload)
}

func (o *GetIdentityPoolIDPNotFound) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/identity_pool/{iid}][%d] getIdentityPoolIdPNotFound  %+v", 404, o.Payload)
}

func (o *GetIdentityPoolIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetIdentityPoolIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetIdentityPoolIDPTooManyRequests creates a GetIdentityPoolIDPTooManyRequests with default headers values
func NewGetIdentityPoolIDPTooManyRequests() *GetIdentityPoolIDPTooManyRequests {
	return &GetIdentityPoolIDPTooManyRequests{}
}

/*
GetIdentityPoolIDPTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetIdentityPoolIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get identity pool Id p too many requests response has a 2xx status code
func (o *GetIdentityPoolIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get identity pool Id p too many requests response has a 3xx status code
func (o *GetIdentityPoolIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get identity pool Id p too many requests response has a 4xx status code
func (o *GetIdentityPoolIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get identity pool Id p too many requests response has a 5xx status code
func (o *GetIdentityPoolIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get identity pool Id p too many requests response a status code equal to that given
func (o *GetIdentityPoolIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get identity pool Id p too many requests response
func (o *GetIdentityPoolIDPTooManyRequests) Code() int {
	return 429
}

func (o *GetIdentityPoolIDPTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/identity_pool/{iid}][%d] getIdentityPoolIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetIdentityPoolIDPTooManyRequests) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/identity_pool/{iid}][%d] getIdentityPoolIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetIdentityPoolIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetIdentityPoolIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
