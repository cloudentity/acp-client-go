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

// CreateAuth0IDPReader is a Reader for the CreateAuth0IDP structure.
type CreateAuth0IDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateAuth0IDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateAuth0IDPCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateAuth0IDPBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateAuth0IDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateAuth0IDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateAuth0IDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateAuth0IDPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateAuth0IDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /servers/{wid}/idps/auth0] createAuth0IDP", response, response.Code())
	}
}

// NewCreateAuth0IDPCreated creates a CreateAuth0IDPCreated with default headers values
func NewCreateAuth0IDPCreated() *CreateAuth0IDPCreated {
	return &CreateAuth0IDPCreated{}
}

/*
CreateAuth0IDPCreated describes a response with status code 201, with default header values.

Auth0IDP
*/
type CreateAuth0IDPCreated struct {
	Payload *models.Auth0IDP
}

// IsSuccess returns true when this create auth0 Id p created response has a 2xx status code
func (o *CreateAuth0IDPCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create auth0 Id p created response has a 3xx status code
func (o *CreateAuth0IDPCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create auth0 Id p created response has a 4xx status code
func (o *CreateAuth0IDPCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create auth0 Id p created response has a 5xx status code
func (o *CreateAuth0IDPCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create auth0 Id p created response a status code equal to that given
func (o *CreateAuth0IDPCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create auth0 Id p created response
func (o *CreateAuth0IDPCreated) Code() int {
	return 201
}

func (o *CreateAuth0IDPCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/auth0][%d] createAuth0IdPCreated %s", 201, payload)
}

func (o *CreateAuth0IDPCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/auth0][%d] createAuth0IdPCreated %s", 201, payload)
}

func (o *CreateAuth0IDPCreated) GetPayload() *models.Auth0IDP {
	return o.Payload
}

func (o *CreateAuth0IDPCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Auth0IDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAuth0IDPBadRequest creates a CreateAuth0IDPBadRequest with default headers values
func NewCreateAuth0IDPBadRequest() *CreateAuth0IDPBadRequest {
	return &CreateAuth0IDPBadRequest{}
}

/*
CreateAuth0IDPBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type CreateAuth0IDPBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this create auth0 Id p bad request response has a 2xx status code
func (o *CreateAuth0IDPBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create auth0 Id p bad request response has a 3xx status code
func (o *CreateAuth0IDPBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create auth0 Id p bad request response has a 4xx status code
func (o *CreateAuth0IDPBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create auth0 Id p bad request response has a 5xx status code
func (o *CreateAuth0IDPBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create auth0 Id p bad request response a status code equal to that given
func (o *CreateAuth0IDPBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create auth0 Id p bad request response
func (o *CreateAuth0IDPBadRequest) Code() int {
	return 400
}

func (o *CreateAuth0IDPBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/auth0][%d] createAuth0IdPBadRequest %s", 400, payload)
}

func (o *CreateAuth0IDPBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/auth0][%d] createAuth0IdPBadRequest %s", 400, payload)
}

func (o *CreateAuth0IDPBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAuth0IDPBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAuth0IDPUnauthorized creates a CreateAuth0IDPUnauthorized with default headers values
func NewCreateAuth0IDPUnauthorized() *CreateAuth0IDPUnauthorized {
	return &CreateAuth0IDPUnauthorized{}
}

/*
CreateAuth0IDPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CreateAuth0IDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this create auth0 Id p unauthorized response has a 2xx status code
func (o *CreateAuth0IDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create auth0 Id p unauthorized response has a 3xx status code
func (o *CreateAuth0IDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create auth0 Id p unauthorized response has a 4xx status code
func (o *CreateAuth0IDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create auth0 Id p unauthorized response has a 5xx status code
func (o *CreateAuth0IDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create auth0 Id p unauthorized response a status code equal to that given
func (o *CreateAuth0IDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the create auth0 Id p unauthorized response
func (o *CreateAuth0IDPUnauthorized) Code() int {
	return 401
}

func (o *CreateAuth0IDPUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/auth0][%d] createAuth0IdPUnauthorized %s", 401, payload)
}

func (o *CreateAuth0IDPUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/auth0][%d] createAuth0IdPUnauthorized %s", 401, payload)
}

func (o *CreateAuth0IDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAuth0IDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAuth0IDPForbidden creates a CreateAuth0IDPForbidden with default headers values
func NewCreateAuth0IDPForbidden() *CreateAuth0IDPForbidden {
	return &CreateAuth0IDPForbidden{}
}

/*
CreateAuth0IDPForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateAuth0IDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this create auth0 Id p forbidden response has a 2xx status code
func (o *CreateAuth0IDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create auth0 Id p forbidden response has a 3xx status code
func (o *CreateAuth0IDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create auth0 Id p forbidden response has a 4xx status code
func (o *CreateAuth0IDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create auth0 Id p forbidden response has a 5xx status code
func (o *CreateAuth0IDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create auth0 Id p forbidden response a status code equal to that given
func (o *CreateAuth0IDPForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create auth0 Id p forbidden response
func (o *CreateAuth0IDPForbidden) Code() int {
	return 403
}

func (o *CreateAuth0IDPForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/auth0][%d] createAuth0IdPForbidden %s", 403, payload)
}

func (o *CreateAuth0IDPForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/auth0][%d] createAuth0IdPForbidden %s", 403, payload)
}

func (o *CreateAuth0IDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAuth0IDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAuth0IDPNotFound creates a CreateAuth0IDPNotFound with default headers values
func NewCreateAuth0IDPNotFound() *CreateAuth0IDPNotFound {
	return &CreateAuth0IDPNotFound{}
}

/*
CreateAuth0IDPNotFound describes a response with status code 404, with default header values.

Not found
*/
type CreateAuth0IDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this create auth0 Id p not found response has a 2xx status code
func (o *CreateAuth0IDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create auth0 Id p not found response has a 3xx status code
func (o *CreateAuth0IDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create auth0 Id p not found response has a 4xx status code
func (o *CreateAuth0IDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this create auth0 Id p not found response has a 5xx status code
func (o *CreateAuth0IDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this create auth0 Id p not found response a status code equal to that given
func (o *CreateAuth0IDPNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the create auth0 Id p not found response
func (o *CreateAuth0IDPNotFound) Code() int {
	return 404
}

func (o *CreateAuth0IDPNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/auth0][%d] createAuth0IdPNotFound %s", 404, payload)
}

func (o *CreateAuth0IDPNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/auth0][%d] createAuth0IdPNotFound %s", 404, payload)
}

func (o *CreateAuth0IDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAuth0IDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAuth0IDPUnprocessableEntity creates a CreateAuth0IDPUnprocessableEntity with default headers values
func NewCreateAuth0IDPUnprocessableEntity() *CreateAuth0IDPUnprocessableEntity {
	return &CreateAuth0IDPUnprocessableEntity{}
}

/*
CreateAuth0IDPUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type CreateAuth0IDPUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this create auth0 Id p unprocessable entity response has a 2xx status code
func (o *CreateAuth0IDPUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create auth0 Id p unprocessable entity response has a 3xx status code
func (o *CreateAuth0IDPUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create auth0 Id p unprocessable entity response has a 4xx status code
func (o *CreateAuth0IDPUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this create auth0 Id p unprocessable entity response has a 5xx status code
func (o *CreateAuth0IDPUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this create auth0 Id p unprocessable entity response a status code equal to that given
func (o *CreateAuth0IDPUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the create auth0 Id p unprocessable entity response
func (o *CreateAuth0IDPUnprocessableEntity) Code() int {
	return 422
}

func (o *CreateAuth0IDPUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/auth0][%d] createAuth0IdPUnprocessableEntity %s", 422, payload)
}

func (o *CreateAuth0IDPUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/auth0][%d] createAuth0IdPUnprocessableEntity %s", 422, payload)
}

func (o *CreateAuth0IDPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAuth0IDPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAuth0IDPTooManyRequests creates a CreateAuth0IDPTooManyRequests with default headers values
func NewCreateAuth0IDPTooManyRequests() *CreateAuth0IDPTooManyRequests {
	return &CreateAuth0IDPTooManyRequests{}
}

/*
CreateAuth0IDPTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type CreateAuth0IDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this create auth0 Id p too many requests response has a 2xx status code
func (o *CreateAuth0IDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create auth0 Id p too many requests response has a 3xx status code
func (o *CreateAuth0IDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create auth0 Id p too many requests response has a 4xx status code
func (o *CreateAuth0IDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create auth0 Id p too many requests response has a 5xx status code
func (o *CreateAuth0IDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create auth0 Id p too many requests response a status code equal to that given
func (o *CreateAuth0IDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create auth0 Id p too many requests response
func (o *CreateAuth0IDPTooManyRequests) Code() int {
	return 429
}

func (o *CreateAuth0IDPTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/auth0][%d] createAuth0IdPTooManyRequests %s", 429, payload)
}

func (o *CreateAuth0IDPTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/auth0][%d] createAuth0IdPTooManyRequests %s", 429, payload)
}

func (o *CreateAuth0IDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAuth0IDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
