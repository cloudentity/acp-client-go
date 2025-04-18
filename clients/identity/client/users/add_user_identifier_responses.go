// Code generated by go-swagger; DO NOT EDIT.

package users

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

// AddUserIdentifierReader is a Reader for the AddUserIdentifier structure.
type AddUserIdentifierReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AddUserIdentifierReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAddUserIdentifierOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewAddUserIdentifierUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewAddUserIdentifierForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewAddUserIdentifierNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewAddUserIdentifierConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewAddUserIdentifierUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /admin/pools/{ipID}/users/{userID}/identifiers/add] addUserIdentifier", response, response.Code())
	}
}

// NewAddUserIdentifierOK creates a AddUserIdentifierOK with default headers values
func NewAddUserIdentifierOK() *AddUserIdentifierOK {
	return &AddUserIdentifierOK{}
}

/*
AddUserIdentifierOK describes a response with status code 200, with default header values.

Identifier
*/
type AddUserIdentifierOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.UserIdentifier
}

// IsSuccess returns true when this add user identifier o k response has a 2xx status code
func (o *AddUserIdentifierOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this add user identifier o k response has a 3xx status code
func (o *AddUserIdentifierOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this add user identifier o k response has a 4xx status code
func (o *AddUserIdentifierOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this add user identifier o k response has a 5xx status code
func (o *AddUserIdentifierOK) IsServerError() bool {
	return false
}

// IsCode returns true when this add user identifier o k response a status code equal to that given
func (o *AddUserIdentifierOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the add user identifier o k response
func (o *AddUserIdentifierOK) Code() int {
	return 200
}

func (o *AddUserIdentifierOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/identifiers/add][%d] addUserIdentifierOK %s", 200, payload)
}

func (o *AddUserIdentifierOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/identifiers/add][%d] addUserIdentifierOK %s", 200, payload)
}

func (o *AddUserIdentifierOK) GetPayload() *models.UserIdentifier {
	return o.Payload
}

func (o *AddUserIdentifierOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.UserIdentifier)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAddUserIdentifierUnauthorized creates a AddUserIdentifierUnauthorized with default headers values
func NewAddUserIdentifierUnauthorized() *AddUserIdentifierUnauthorized {
	return &AddUserIdentifierUnauthorized{}
}

/*
AddUserIdentifierUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type AddUserIdentifierUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this add user identifier unauthorized response has a 2xx status code
func (o *AddUserIdentifierUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this add user identifier unauthorized response has a 3xx status code
func (o *AddUserIdentifierUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this add user identifier unauthorized response has a 4xx status code
func (o *AddUserIdentifierUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this add user identifier unauthorized response has a 5xx status code
func (o *AddUserIdentifierUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this add user identifier unauthorized response a status code equal to that given
func (o *AddUserIdentifierUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the add user identifier unauthorized response
func (o *AddUserIdentifierUnauthorized) Code() int {
	return 401
}

func (o *AddUserIdentifierUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/identifiers/add][%d] addUserIdentifierUnauthorized %s", 401, payload)
}

func (o *AddUserIdentifierUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/identifiers/add][%d] addUserIdentifierUnauthorized %s", 401, payload)
}

func (o *AddUserIdentifierUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *AddUserIdentifierUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAddUserIdentifierForbidden creates a AddUserIdentifierForbidden with default headers values
func NewAddUserIdentifierForbidden() *AddUserIdentifierForbidden {
	return &AddUserIdentifierForbidden{}
}

/*
AddUserIdentifierForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type AddUserIdentifierForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this add user identifier forbidden response has a 2xx status code
func (o *AddUserIdentifierForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this add user identifier forbidden response has a 3xx status code
func (o *AddUserIdentifierForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this add user identifier forbidden response has a 4xx status code
func (o *AddUserIdentifierForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this add user identifier forbidden response has a 5xx status code
func (o *AddUserIdentifierForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this add user identifier forbidden response a status code equal to that given
func (o *AddUserIdentifierForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the add user identifier forbidden response
func (o *AddUserIdentifierForbidden) Code() int {
	return 403
}

func (o *AddUserIdentifierForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/identifiers/add][%d] addUserIdentifierForbidden %s", 403, payload)
}

func (o *AddUserIdentifierForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/identifiers/add][%d] addUserIdentifierForbidden %s", 403, payload)
}

func (o *AddUserIdentifierForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *AddUserIdentifierForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAddUserIdentifierNotFound creates a AddUserIdentifierNotFound with default headers values
func NewAddUserIdentifierNotFound() *AddUserIdentifierNotFound {
	return &AddUserIdentifierNotFound{}
}

/*
AddUserIdentifierNotFound describes a response with status code 404, with default header values.

Not found
*/
type AddUserIdentifierNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this add user identifier not found response has a 2xx status code
func (o *AddUserIdentifierNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this add user identifier not found response has a 3xx status code
func (o *AddUserIdentifierNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this add user identifier not found response has a 4xx status code
func (o *AddUserIdentifierNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this add user identifier not found response has a 5xx status code
func (o *AddUserIdentifierNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this add user identifier not found response a status code equal to that given
func (o *AddUserIdentifierNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the add user identifier not found response
func (o *AddUserIdentifierNotFound) Code() int {
	return 404
}

func (o *AddUserIdentifierNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/identifiers/add][%d] addUserIdentifierNotFound %s", 404, payload)
}

func (o *AddUserIdentifierNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/identifiers/add][%d] addUserIdentifierNotFound %s", 404, payload)
}

func (o *AddUserIdentifierNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *AddUserIdentifierNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAddUserIdentifierConflict creates a AddUserIdentifierConflict with default headers values
func NewAddUserIdentifierConflict() *AddUserIdentifierConflict {
	return &AddUserIdentifierConflict{}
}

/*
AddUserIdentifierConflict describes a response with status code 409, with default header values.

Conflict
*/
type AddUserIdentifierConflict struct {
	Payload *models.Error
}

// IsSuccess returns true when this add user identifier conflict response has a 2xx status code
func (o *AddUserIdentifierConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this add user identifier conflict response has a 3xx status code
func (o *AddUserIdentifierConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this add user identifier conflict response has a 4xx status code
func (o *AddUserIdentifierConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this add user identifier conflict response has a 5xx status code
func (o *AddUserIdentifierConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this add user identifier conflict response a status code equal to that given
func (o *AddUserIdentifierConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the add user identifier conflict response
func (o *AddUserIdentifierConflict) Code() int {
	return 409
}

func (o *AddUserIdentifierConflict) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/identifiers/add][%d] addUserIdentifierConflict %s", 409, payload)
}

func (o *AddUserIdentifierConflict) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/identifiers/add][%d] addUserIdentifierConflict %s", 409, payload)
}

func (o *AddUserIdentifierConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *AddUserIdentifierConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAddUserIdentifierUnprocessableEntity creates a AddUserIdentifierUnprocessableEntity with default headers values
func NewAddUserIdentifierUnprocessableEntity() *AddUserIdentifierUnprocessableEntity {
	return &AddUserIdentifierUnprocessableEntity{}
}

/*
AddUserIdentifierUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type AddUserIdentifierUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this add user identifier unprocessable entity response has a 2xx status code
func (o *AddUserIdentifierUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this add user identifier unprocessable entity response has a 3xx status code
func (o *AddUserIdentifierUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this add user identifier unprocessable entity response has a 4xx status code
func (o *AddUserIdentifierUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this add user identifier unprocessable entity response has a 5xx status code
func (o *AddUserIdentifierUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this add user identifier unprocessable entity response a status code equal to that given
func (o *AddUserIdentifierUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the add user identifier unprocessable entity response
func (o *AddUserIdentifierUnprocessableEntity) Code() int {
	return 422
}

func (o *AddUserIdentifierUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/identifiers/add][%d] addUserIdentifierUnprocessableEntity %s", 422, payload)
}

func (o *AddUserIdentifierUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/identifiers/add][%d] addUserIdentifierUnprocessableEntity %s", 422, payload)
}

func (o *AddUserIdentifierUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *AddUserIdentifierUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
