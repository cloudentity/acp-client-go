// Code generated by go-swagger; DO NOT EDIT.

package groups

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identity/models"
)

// GetGroupReader is a Reader for the GetGroup structure.
type GetGroupReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetGroupReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetGroupOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetGroupUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetGroupForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetGroupNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetGroupTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /admin/pools/{ipID}/groups/{groupID}] getGroup", response, response.Code())
	}
}

// NewGetGroupOK creates a GetGroupOK with default headers values
func NewGetGroupOK() *GetGroupOK {
	return &GetGroupOK{}
}

/*
GetGroupOK describes a response with status code 200, with default header values.

Group
*/
type GetGroupOK struct {
	Payload *models.Group
}

// IsSuccess returns true when this get group o k response has a 2xx status code
func (o *GetGroupOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get group o k response has a 3xx status code
func (o *GetGroupOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get group o k response has a 4xx status code
func (o *GetGroupOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get group o k response has a 5xx status code
func (o *GetGroupOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get group o k response a status code equal to that given
func (o *GetGroupOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get group o k response
func (o *GetGroupOK) Code() int {
	return 200
}

func (o *GetGroupOK) Error() string {
	return fmt.Sprintf("[GET /admin/pools/{ipID}/groups/{groupID}][%d] getGroupOK  %+v", 200, o.Payload)
}

func (o *GetGroupOK) String() string {
	return fmt.Sprintf("[GET /admin/pools/{ipID}/groups/{groupID}][%d] getGroupOK  %+v", 200, o.Payload)
}

func (o *GetGroupOK) GetPayload() *models.Group {
	return o.Payload
}

func (o *GetGroupOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Group)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetGroupUnauthorized creates a GetGroupUnauthorized with default headers values
func NewGetGroupUnauthorized() *GetGroupUnauthorized {
	return &GetGroupUnauthorized{}
}

/*
GetGroupUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetGroupUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get group unauthorized response has a 2xx status code
func (o *GetGroupUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get group unauthorized response has a 3xx status code
func (o *GetGroupUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get group unauthorized response has a 4xx status code
func (o *GetGroupUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get group unauthorized response has a 5xx status code
func (o *GetGroupUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get group unauthorized response a status code equal to that given
func (o *GetGroupUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get group unauthorized response
func (o *GetGroupUnauthorized) Code() int {
	return 401
}

func (o *GetGroupUnauthorized) Error() string {
	return fmt.Sprintf("[GET /admin/pools/{ipID}/groups/{groupID}][%d] getGroupUnauthorized  %+v", 401, o.Payload)
}

func (o *GetGroupUnauthorized) String() string {
	return fmt.Sprintf("[GET /admin/pools/{ipID}/groups/{groupID}][%d] getGroupUnauthorized  %+v", 401, o.Payload)
}

func (o *GetGroupUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGroupUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetGroupForbidden creates a GetGroupForbidden with default headers values
func NewGetGroupForbidden() *GetGroupForbidden {
	return &GetGroupForbidden{}
}

/*
GetGroupForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetGroupForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get group forbidden response has a 2xx status code
func (o *GetGroupForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get group forbidden response has a 3xx status code
func (o *GetGroupForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get group forbidden response has a 4xx status code
func (o *GetGroupForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get group forbidden response has a 5xx status code
func (o *GetGroupForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get group forbidden response a status code equal to that given
func (o *GetGroupForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get group forbidden response
func (o *GetGroupForbidden) Code() int {
	return 403
}

func (o *GetGroupForbidden) Error() string {
	return fmt.Sprintf("[GET /admin/pools/{ipID}/groups/{groupID}][%d] getGroupForbidden  %+v", 403, o.Payload)
}

func (o *GetGroupForbidden) String() string {
	return fmt.Sprintf("[GET /admin/pools/{ipID}/groups/{groupID}][%d] getGroupForbidden  %+v", 403, o.Payload)
}

func (o *GetGroupForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGroupForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetGroupNotFound creates a GetGroupNotFound with default headers values
func NewGetGroupNotFound() *GetGroupNotFound {
	return &GetGroupNotFound{}
}

/*
GetGroupNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetGroupNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get group not found response has a 2xx status code
func (o *GetGroupNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get group not found response has a 3xx status code
func (o *GetGroupNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get group not found response has a 4xx status code
func (o *GetGroupNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get group not found response has a 5xx status code
func (o *GetGroupNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get group not found response a status code equal to that given
func (o *GetGroupNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get group not found response
func (o *GetGroupNotFound) Code() int {
	return 404
}

func (o *GetGroupNotFound) Error() string {
	return fmt.Sprintf("[GET /admin/pools/{ipID}/groups/{groupID}][%d] getGroupNotFound  %+v", 404, o.Payload)
}

func (o *GetGroupNotFound) String() string {
	return fmt.Sprintf("[GET /admin/pools/{ipID}/groups/{groupID}][%d] getGroupNotFound  %+v", 404, o.Payload)
}

func (o *GetGroupNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGroupNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetGroupTooManyRequests creates a GetGroupTooManyRequests with default headers values
func NewGetGroupTooManyRequests() *GetGroupTooManyRequests {
	return &GetGroupTooManyRequests{}
}

/*
GetGroupTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetGroupTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get group too many requests response has a 2xx status code
func (o *GetGroupTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get group too many requests response has a 3xx status code
func (o *GetGroupTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get group too many requests response has a 4xx status code
func (o *GetGroupTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get group too many requests response has a 5xx status code
func (o *GetGroupTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get group too many requests response a status code equal to that given
func (o *GetGroupTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get group too many requests response
func (o *GetGroupTooManyRequests) Code() int {
	return 429
}

func (o *GetGroupTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /admin/pools/{ipID}/groups/{groupID}][%d] getGroupTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetGroupTooManyRequests) String() string {
	return fmt.Sprintf("[GET /admin/pools/{ipID}/groups/{groupID}][%d] getGroupTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetGroupTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGroupTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
