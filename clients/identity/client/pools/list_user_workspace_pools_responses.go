// Code generated by go-swagger; DO NOT EDIT.

package pools

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identity/models"
)

// ListUserWorkspacePoolsReader is a Reader for the ListUserWorkspacePools structure.
type ListUserWorkspacePoolsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListUserWorkspacePoolsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListUserWorkspacePoolsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListUserWorkspacePoolsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListUserWorkspacePoolsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListUserWorkspacePoolsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /admin/workspace/{wid}/user/pools] listUserWorkspacePools", response, response.Code())
	}
}

// NewListUserWorkspacePoolsOK creates a ListUserWorkspacePoolsOK with default headers values
func NewListUserWorkspacePoolsOK() *ListUserWorkspacePoolsOK {
	return &ListUserWorkspacePoolsOK{}
}

/*
ListUserWorkspacePoolsOK describes a response with status code 200, with default header values.

UserPools
*/
type ListUserWorkspacePoolsOK struct {
	Payload *models.UserPools
}

// IsSuccess returns true when this list user workspace pools o k response has a 2xx status code
func (o *ListUserWorkspacePoolsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list user workspace pools o k response has a 3xx status code
func (o *ListUserWorkspacePoolsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list user workspace pools o k response has a 4xx status code
func (o *ListUserWorkspacePoolsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list user workspace pools o k response has a 5xx status code
func (o *ListUserWorkspacePoolsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list user workspace pools o k response a status code equal to that given
func (o *ListUserWorkspacePoolsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the list user workspace pools o k response
func (o *ListUserWorkspacePoolsOK) Code() int {
	return 200
}

func (o *ListUserWorkspacePoolsOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/workspace/{wid}/user/pools][%d] listUserWorkspacePoolsOK %s", 200, payload)
}

func (o *ListUserWorkspacePoolsOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/workspace/{wid}/user/pools][%d] listUserWorkspacePoolsOK %s", 200, payload)
}

func (o *ListUserWorkspacePoolsOK) GetPayload() *models.UserPools {
	return o.Payload
}

func (o *ListUserWorkspacePoolsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.UserPools)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListUserWorkspacePoolsUnauthorized creates a ListUserWorkspacePoolsUnauthorized with default headers values
func NewListUserWorkspacePoolsUnauthorized() *ListUserWorkspacePoolsUnauthorized {
	return &ListUserWorkspacePoolsUnauthorized{}
}

/*
ListUserWorkspacePoolsUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type ListUserWorkspacePoolsUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list user workspace pools unauthorized response has a 2xx status code
func (o *ListUserWorkspacePoolsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list user workspace pools unauthorized response has a 3xx status code
func (o *ListUserWorkspacePoolsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list user workspace pools unauthorized response has a 4xx status code
func (o *ListUserWorkspacePoolsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list user workspace pools unauthorized response has a 5xx status code
func (o *ListUserWorkspacePoolsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list user workspace pools unauthorized response a status code equal to that given
func (o *ListUserWorkspacePoolsUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the list user workspace pools unauthorized response
func (o *ListUserWorkspacePoolsUnauthorized) Code() int {
	return 401
}

func (o *ListUserWorkspacePoolsUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/workspace/{wid}/user/pools][%d] listUserWorkspacePoolsUnauthorized %s", 401, payload)
}

func (o *ListUserWorkspacePoolsUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/workspace/{wid}/user/pools][%d] listUserWorkspacePoolsUnauthorized %s", 401, payload)
}

func (o *ListUserWorkspacePoolsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListUserWorkspacePoolsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListUserWorkspacePoolsForbidden creates a ListUserWorkspacePoolsForbidden with default headers values
func NewListUserWorkspacePoolsForbidden() *ListUserWorkspacePoolsForbidden {
	return &ListUserWorkspacePoolsForbidden{}
}

/*
ListUserWorkspacePoolsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ListUserWorkspacePoolsForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list user workspace pools forbidden response has a 2xx status code
func (o *ListUserWorkspacePoolsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list user workspace pools forbidden response has a 3xx status code
func (o *ListUserWorkspacePoolsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list user workspace pools forbidden response has a 4xx status code
func (o *ListUserWorkspacePoolsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list user workspace pools forbidden response has a 5xx status code
func (o *ListUserWorkspacePoolsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list user workspace pools forbidden response a status code equal to that given
func (o *ListUserWorkspacePoolsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the list user workspace pools forbidden response
func (o *ListUserWorkspacePoolsForbidden) Code() int {
	return 403
}

func (o *ListUserWorkspacePoolsForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/workspace/{wid}/user/pools][%d] listUserWorkspacePoolsForbidden %s", 403, payload)
}

func (o *ListUserWorkspacePoolsForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/workspace/{wid}/user/pools][%d] listUserWorkspacePoolsForbidden %s", 403, payload)
}

func (o *ListUserWorkspacePoolsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListUserWorkspacePoolsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListUserWorkspacePoolsTooManyRequests creates a ListUserWorkspacePoolsTooManyRequests with default headers values
func NewListUserWorkspacePoolsTooManyRequests() *ListUserWorkspacePoolsTooManyRequests {
	return &ListUserWorkspacePoolsTooManyRequests{}
}

/*
ListUserWorkspacePoolsTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type ListUserWorkspacePoolsTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list user workspace pools too many requests response has a 2xx status code
func (o *ListUserWorkspacePoolsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list user workspace pools too many requests response has a 3xx status code
func (o *ListUserWorkspacePoolsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list user workspace pools too many requests response has a 4xx status code
func (o *ListUserWorkspacePoolsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list user workspace pools too many requests response has a 5xx status code
func (o *ListUserWorkspacePoolsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list user workspace pools too many requests response a status code equal to that given
func (o *ListUserWorkspacePoolsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the list user workspace pools too many requests response
func (o *ListUserWorkspacePoolsTooManyRequests) Code() int {
	return 429
}

func (o *ListUserWorkspacePoolsTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/workspace/{wid}/user/pools][%d] listUserWorkspacePoolsTooManyRequests %s", 429, payload)
}

func (o *ListUserWorkspacePoolsTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/workspace/{wid}/user/pools][%d] listUserWorkspacePoolsTooManyRequests %s", 429, payload)
}

func (o *ListUserWorkspacePoolsTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListUserWorkspacePoolsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
