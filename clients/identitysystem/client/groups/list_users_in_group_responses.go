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

	"github.com/cloudentity/acp-client-go/clients/identitysystem/models"
)

// ListUsersInGroupReader is a Reader for the ListUsersInGroup structure.
type ListUsersInGroupReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListUsersInGroupReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListUsersInGroupOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewListUsersInGroupBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewListUsersInGroupUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListUsersInGroupForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewListUsersInGroupNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewListUsersInGroupUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListUsersInGroupTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /system/pools/{ipID}/groups/{groupID}/users] listUsersInGroup", response, response.Code())
	}
}

// NewListUsersInGroupOK creates a ListUsersInGroupOK with default headers values
func NewListUsersInGroupOK() *ListUsersInGroupOK {
	return &ListUsersInGroupOK{}
}

/*
ListUsersInGroupOK describes a response with status code 200, with default header values.

Identity Users
*/
type ListUsersInGroupOK struct {
	Payload *models.Users
}

// IsSuccess returns true when this list users in group o k response has a 2xx status code
func (o *ListUsersInGroupOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list users in group o k response has a 3xx status code
func (o *ListUsersInGroupOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list users in group o k response has a 4xx status code
func (o *ListUsersInGroupOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list users in group o k response has a 5xx status code
func (o *ListUsersInGroupOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list users in group o k response a status code equal to that given
func (o *ListUsersInGroupOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the list users in group o k response
func (o *ListUsersInGroupOK) Code() int {
	return 200
}

func (o *ListUsersInGroupOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /system/pools/{ipID}/groups/{groupID}/users][%d] listUsersInGroupOK %s", 200, payload)
}

func (o *ListUsersInGroupOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /system/pools/{ipID}/groups/{groupID}/users][%d] listUsersInGroupOK %s", 200, payload)
}

func (o *ListUsersInGroupOK) GetPayload() *models.Users {
	return o.Payload
}

func (o *ListUsersInGroupOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Users)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListUsersInGroupBadRequest creates a ListUsersInGroupBadRequest with default headers values
func NewListUsersInGroupBadRequest() *ListUsersInGroupBadRequest {
	return &ListUsersInGroupBadRequest{}
}

/*
ListUsersInGroupBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type ListUsersInGroupBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this list users in group bad request response has a 2xx status code
func (o *ListUsersInGroupBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list users in group bad request response has a 3xx status code
func (o *ListUsersInGroupBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list users in group bad request response has a 4xx status code
func (o *ListUsersInGroupBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this list users in group bad request response has a 5xx status code
func (o *ListUsersInGroupBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this list users in group bad request response a status code equal to that given
func (o *ListUsersInGroupBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the list users in group bad request response
func (o *ListUsersInGroupBadRequest) Code() int {
	return 400
}

func (o *ListUsersInGroupBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /system/pools/{ipID}/groups/{groupID}/users][%d] listUsersInGroupBadRequest %s", 400, payload)
}

func (o *ListUsersInGroupBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /system/pools/{ipID}/groups/{groupID}/users][%d] listUsersInGroupBadRequest %s", 400, payload)
}

func (o *ListUsersInGroupBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListUsersInGroupBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListUsersInGroupUnauthorized creates a ListUsersInGroupUnauthorized with default headers values
func NewListUsersInGroupUnauthorized() *ListUsersInGroupUnauthorized {
	return &ListUsersInGroupUnauthorized{}
}

/*
ListUsersInGroupUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type ListUsersInGroupUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list users in group unauthorized response has a 2xx status code
func (o *ListUsersInGroupUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list users in group unauthorized response has a 3xx status code
func (o *ListUsersInGroupUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list users in group unauthorized response has a 4xx status code
func (o *ListUsersInGroupUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list users in group unauthorized response has a 5xx status code
func (o *ListUsersInGroupUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list users in group unauthorized response a status code equal to that given
func (o *ListUsersInGroupUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the list users in group unauthorized response
func (o *ListUsersInGroupUnauthorized) Code() int {
	return 401
}

func (o *ListUsersInGroupUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /system/pools/{ipID}/groups/{groupID}/users][%d] listUsersInGroupUnauthorized %s", 401, payload)
}

func (o *ListUsersInGroupUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /system/pools/{ipID}/groups/{groupID}/users][%d] listUsersInGroupUnauthorized %s", 401, payload)
}

func (o *ListUsersInGroupUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListUsersInGroupUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListUsersInGroupForbidden creates a ListUsersInGroupForbidden with default headers values
func NewListUsersInGroupForbidden() *ListUsersInGroupForbidden {
	return &ListUsersInGroupForbidden{}
}

/*
ListUsersInGroupForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ListUsersInGroupForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list users in group forbidden response has a 2xx status code
func (o *ListUsersInGroupForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list users in group forbidden response has a 3xx status code
func (o *ListUsersInGroupForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list users in group forbidden response has a 4xx status code
func (o *ListUsersInGroupForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list users in group forbidden response has a 5xx status code
func (o *ListUsersInGroupForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list users in group forbidden response a status code equal to that given
func (o *ListUsersInGroupForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the list users in group forbidden response
func (o *ListUsersInGroupForbidden) Code() int {
	return 403
}

func (o *ListUsersInGroupForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /system/pools/{ipID}/groups/{groupID}/users][%d] listUsersInGroupForbidden %s", 403, payload)
}

func (o *ListUsersInGroupForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /system/pools/{ipID}/groups/{groupID}/users][%d] listUsersInGroupForbidden %s", 403, payload)
}

func (o *ListUsersInGroupForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListUsersInGroupForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListUsersInGroupNotFound creates a ListUsersInGroupNotFound with default headers values
func NewListUsersInGroupNotFound() *ListUsersInGroupNotFound {
	return &ListUsersInGroupNotFound{}
}

/*
ListUsersInGroupNotFound describes a response with status code 404, with default header values.

Not found
*/
type ListUsersInGroupNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this list users in group not found response has a 2xx status code
func (o *ListUsersInGroupNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list users in group not found response has a 3xx status code
func (o *ListUsersInGroupNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list users in group not found response has a 4xx status code
func (o *ListUsersInGroupNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this list users in group not found response has a 5xx status code
func (o *ListUsersInGroupNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this list users in group not found response a status code equal to that given
func (o *ListUsersInGroupNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the list users in group not found response
func (o *ListUsersInGroupNotFound) Code() int {
	return 404
}

func (o *ListUsersInGroupNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /system/pools/{ipID}/groups/{groupID}/users][%d] listUsersInGroupNotFound %s", 404, payload)
}

func (o *ListUsersInGroupNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /system/pools/{ipID}/groups/{groupID}/users][%d] listUsersInGroupNotFound %s", 404, payload)
}

func (o *ListUsersInGroupNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListUsersInGroupNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListUsersInGroupUnprocessableEntity creates a ListUsersInGroupUnprocessableEntity with default headers values
func NewListUsersInGroupUnprocessableEntity() *ListUsersInGroupUnprocessableEntity {
	return &ListUsersInGroupUnprocessableEntity{}
}

/*
ListUsersInGroupUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type ListUsersInGroupUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this list users in group unprocessable entity response has a 2xx status code
func (o *ListUsersInGroupUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list users in group unprocessable entity response has a 3xx status code
func (o *ListUsersInGroupUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list users in group unprocessable entity response has a 4xx status code
func (o *ListUsersInGroupUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this list users in group unprocessable entity response has a 5xx status code
func (o *ListUsersInGroupUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this list users in group unprocessable entity response a status code equal to that given
func (o *ListUsersInGroupUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the list users in group unprocessable entity response
func (o *ListUsersInGroupUnprocessableEntity) Code() int {
	return 422
}

func (o *ListUsersInGroupUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /system/pools/{ipID}/groups/{groupID}/users][%d] listUsersInGroupUnprocessableEntity %s", 422, payload)
}

func (o *ListUsersInGroupUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /system/pools/{ipID}/groups/{groupID}/users][%d] listUsersInGroupUnprocessableEntity %s", 422, payload)
}

func (o *ListUsersInGroupUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListUsersInGroupUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListUsersInGroupTooManyRequests creates a ListUsersInGroupTooManyRequests with default headers values
func NewListUsersInGroupTooManyRequests() *ListUsersInGroupTooManyRequests {
	return &ListUsersInGroupTooManyRequests{}
}

/*
ListUsersInGroupTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type ListUsersInGroupTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list users in group too many requests response has a 2xx status code
func (o *ListUsersInGroupTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list users in group too many requests response has a 3xx status code
func (o *ListUsersInGroupTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list users in group too many requests response has a 4xx status code
func (o *ListUsersInGroupTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list users in group too many requests response has a 5xx status code
func (o *ListUsersInGroupTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list users in group too many requests response a status code equal to that given
func (o *ListUsersInGroupTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the list users in group too many requests response
func (o *ListUsersInGroupTooManyRequests) Code() int {
	return 429
}

func (o *ListUsersInGroupTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /system/pools/{ipID}/groups/{groupID}/users][%d] listUsersInGroupTooManyRequests %s", 429, payload)
}

func (o *ListUsersInGroupTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /system/pools/{ipID}/groups/{groupID}/users][%d] listUsersInGroupTooManyRequests %s", 429, payload)
}

func (o *ListUsersInGroupTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListUsersInGroupTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
