// Code generated by go-swagger; DO NOT EDIT.

package groups

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

// IsUserInGroupReader is a Reader for the IsUserInGroup structure.
type IsUserInGroupReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *IsUserInGroupReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewIsUserInGroupNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewIsUserInGroupUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewIsUserInGroupForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewIsUserInGroupNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewIsUserInGroupTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /admin/pools/{ipID}/users/{userID}/groups/{groupID}] isUserInGroup", response, response.Code())
	}
}

// NewIsUserInGroupNoContent creates a IsUserInGroupNoContent with default headers values
func NewIsUserInGroupNoContent() *IsUserInGroupNoContent {
	return &IsUserInGroupNoContent{}
}

/*
IsUserInGroupNoContent describes a response with status code 204, with default header values.

	User is in group
*/
type IsUserInGroupNoContent struct {
}

// IsSuccess returns true when this is user in group no content response has a 2xx status code
func (o *IsUserInGroupNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this is user in group no content response has a 3xx status code
func (o *IsUserInGroupNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this is user in group no content response has a 4xx status code
func (o *IsUserInGroupNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this is user in group no content response has a 5xx status code
func (o *IsUserInGroupNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this is user in group no content response a status code equal to that given
func (o *IsUserInGroupNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the is user in group no content response
func (o *IsUserInGroupNoContent) Code() int {
	return 204
}

func (o *IsUserInGroupNoContent) Error() string {
	return fmt.Sprintf("[GET /admin/pools/{ipID}/users/{userID}/groups/{groupID}][%d] isUserInGroupNoContent", 204)
}

func (o *IsUserInGroupNoContent) String() string {
	return fmt.Sprintf("[GET /admin/pools/{ipID}/users/{userID}/groups/{groupID}][%d] isUserInGroupNoContent", 204)
}

func (o *IsUserInGroupNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewIsUserInGroupUnauthorized creates a IsUserInGroupUnauthorized with default headers values
func NewIsUserInGroupUnauthorized() *IsUserInGroupUnauthorized {
	return &IsUserInGroupUnauthorized{}
}

/*
IsUserInGroupUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type IsUserInGroupUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this is user in group unauthorized response has a 2xx status code
func (o *IsUserInGroupUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this is user in group unauthorized response has a 3xx status code
func (o *IsUserInGroupUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this is user in group unauthorized response has a 4xx status code
func (o *IsUserInGroupUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this is user in group unauthorized response has a 5xx status code
func (o *IsUserInGroupUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this is user in group unauthorized response a status code equal to that given
func (o *IsUserInGroupUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the is user in group unauthorized response
func (o *IsUserInGroupUnauthorized) Code() int {
	return 401
}

func (o *IsUserInGroupUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/pools/{ipID}/users/{userID}/groups/{groupID}][%d] isUserInGroupUnauthorized %s", 401, payload)
}

func (o *IsUserInGroupUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/pools/{ipID}/users/{userID}/groups/{groupID}][%d] isUserInGroupUnauthorized %s", 401, payload)
}

func (o *IsUserInGroupUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *IsUserInGroupUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewIsUserInGroupForbidden creates a IsUserInGroupForbidden with default headers values
func NewIsUserInGroupForbidden() *IsUserInGroupForbidden {
	return &IsUserInGroupForbidden{}
}

/*
IsUserInGroupForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type IsUserInGroupForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this is user in group forbidden response has a 2xx status code
func (o *IsUserInGroupForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this is user in group forbidden response has a 3xx status code
func (o *IsUserInGroupForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this is user in group forbidden response has a 4xx status code
func (o *IsUserInGroupForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this is user in group forbidden response has a 5xx status code
func (o *IsUserInGroupForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this is user in group forbidden response a status code equal to that given
func (o *IsUserInGroupForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the is user in group forbidden response
func (o *IsUserInGroupForbidden) Code() int {
	return 403
}

func (o *IsUserInGroupForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/pools/{ipID}/users/{userID}/groups/{groupID}][%d] isUserInGroupForbidden %s", 403, payload)
}

func (o *IsUserInGroupForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/pools/{ipID}/users/{userID}/groups/{groupID}][%d] isUserInGroupForbidden %s", 403, payload)
}

func (o *IsUserInGroupForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *IsUserInGroupForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewIsUserInGroupNotFound creates a IsUserInGroupNotFound with default headers values
func NewIsUserInGroupNotFound() *IsUserInGroupNotFound {
	return &IsUserInGroupNotFound{}
}

/*
IsUserInGroupNotFound describes a response with status code 404, with default header values.

Not found
*/
type IsUserInGroupNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this is user in group not found response has a 2xx status code
func (o *IsUserInGroupNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this is user in group not found response has a 3xx status code
func (o *IsUserInGroupNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this is user in group not found response has a 4xx status code
func (o *IsUserInGroupNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this is user in group not found response has a 5xx status code
func (o *IsUserInGroupNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this is user in group not found response a status code equal to that given
func (o *IsUserInGroupNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the is user in group not found response
func (o *IsUserInGroupNotFound) Code() int {
	return 404
}

func (o *IsUserInGroupNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/pools/{ipID}/users/{userID}/groups/{groupID}][%d] isUserInGroupNotFound %s", 404, payload)
}

func (o *IsUserInGroupNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/pools/{ipID}/users/{userID}/groups/{groupID}][%d] isUserInGroupNotFound %s", 404, payload)
}

func (o *IsUserInGroupNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *IsUserInGroupNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewIsUserInGroupTooManyRequests creates a IsUserInGroupTooManyRequests with default headers values
func NewIsUserInGroupTooManyRequests() *IsUserInGroupTooManyRequests {
	return &IsUserInGroupTooManyRequests{}
}

/*
IsUserInGroupTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type IsUserInGroupTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this is user in group too many requests response has a 2xx status code
func (o *IsUserInGroupTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this is user in group too many requests response has a 3xx status code
func (o *IsUserInGroupTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this is user in group too many requests response has a 4xx status code
func (o *IsUserInGroupTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this is user in group too many requests response has a 5xx status code
func (o *IsUserInGroupTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this is user in group too many requests response a status code equal to that given
func (o *IsUserInGroupTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the is user in group too many requests response
func (o *IsUserInGroupTooManyRequests) Code() int {
	return 429
}

func (o *IsUserInGroupTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/pools/{ipID}/users/{userID}/groups/{groupID}][%d] isUserInGroupTooManyRequests %s", 429, payload)
}

func (o *IsUserInGroupTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/pools/{ipID}/users/{userID}/groups/{groupID}][%d] isUserInGroupTooManyRequests %s", 429, payload)
}

func (o *IsUserInGroupTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *IsUserInGroupTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
