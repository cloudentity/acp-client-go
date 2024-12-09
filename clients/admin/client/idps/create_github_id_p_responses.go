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

// CreateGithubIDPReader is a Reader for the CreateGithubIDP structure.
type CreateGithubIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateGithubIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateGithubIDPCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateGithubIDPBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateGithubIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateGithubIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateGithubIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateGithubIDPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateGithubIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /servers/{wid}/idps/github] createGithubIDP", response, response.Code())
	}
}

// NewCreateGithubIDPCreated creates a CreateGithubIDPCreated with default headers values
func NewCreateGithubIDPCreated() *CreateGithubIDPCreated {
	return &CreateGithubIDPCreated{}
}

/*
CreateGithubIDPCreated describes a response with status code 201, with default header values.

GithubIDP
*/
type CreateGithubIDPCreated struct {
	Payload *models.GithubIDP
}

// IsSuccess returns true when this create github Id p created response has a 2xx status code
func (o *CreateGithubIDPCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create github Id p created response has a 3xx status code
func (o *CreateGithubIDPCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create github Id p created response has a 4xx status code
func (o *CreateGithubIDPCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create github Id p created response has a 5xx status code
func (o *CreateGithubIDPCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create github Id p created response a status code equal to that given
func (o *CreateGithubIDPCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create github Id p created response
func (o *CreateGithubIDPCreated) Code() int {
	return 201
}

func (o *CreateGithubIDPCreated) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/github][%d] createGithubIdPCreated  %+v", 201, o.Payload)
}

func (o *CreateGithubIDPCreated) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/github][%d] createGithubIdPCreated  %+v", 201, o.Payload)
}

func (o *CreateGithubIDPCreated) GetPayload() *models.GithubIDP {
	return o.Payload
}

func (o *CreateGithubIDPCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GithubIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateGithubIDPBadRequest creates a CreateGithubIDPBadRequest with default headers values
func NewCreateGithubIDPBadRequest() *CreateGithubIDPBadRequest {
	return &CreateGithubIDPBadRequest{}
}

/*
CreateGithubIDPBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type CreateGithubIDPBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this create github Id p bad request response has a 2xx status code
func (o *CreateGithubIDPBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create github Id p bad request response has a 3xx status code
func (o *CreateGithubIDPBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create github Id p bad request response has a 4xx status code
func (o *CreateGithubIDPBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create github Id p bad request response has a 5xx status code
func (o *CreateGithubIDPBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create github Id p bad request response a status code equal to that given
func (o *CreateGithubIDPBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create github Id p bad request response
func (o *CreateGithubIDPBadRequest) Code() int {
	return 400
}

func (o *CreateGithubIDPBadRequest) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/github][%d] createGithubIdPBadRequest  %+v", 400, o.Payload)
}

func (o *CreateGithubIDPBadRequest) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/github][%d] createGithubIdPBadRequest  %+v", 400, o.Payload)
}

func (o *CreateGithubIDPBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateGithubIDPBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateGithubIDPUnauthorized creates a CreateGithubIDPUnauthorized with default headers values
func NewCreateGithubIDPUnauthorized() *CreateGithubIDPUnauthorized {
	return &CreateGithubIDPUnauthorized{}
}

/*
CreateGithubIDPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CreateGithubIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this create github Id p unauthorized response has a 2xx status code
func (o *CreateGithubIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create github Id p unauthorized response has a 3xx status code
func (o *CreateGithubIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create github Id p unauthorized response has a 4xx status code
func (o *CreateGithubIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create github Id p unauthorized response has a 5xx status code
func (o *CreateGithubIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create github Id p unauthorized response a status code equal to that given
func (o *CreateGithubIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the create github Id p unauthorized response
func (o *CreateGithubIDPUnauthorized) Code() int {
	return 401
}

func (o *CreateGithubIDPUnauthorized) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/github][%d] createGithubIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateGithubIDPUnauthorized) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/github][%d] createGithubIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateGithubIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateGithubIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateGithubIDPForbidden creates a CreateGithubIDPForbidden with default headers values
func NewCreateGithubIDPForbidden() *CreateGithubIDPForbidden {
	return &CreateGithubIDPForbidden{}
}

/*
CreateGithubIDPForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateGithubIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this create github Id p forbidden response has a 2xx status code
func (o *CreateGithubIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create github Id p forbidden response has a 3xx status code
func (o *CreateGithubIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create github Id p forbidden response has a 4xx status code
func (o *CreateGithubIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create github Id p forbidden response has a 5xx status code
func (o *CreateGithubIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create github Id p forbidden response a status code equal to that given
func (o *CreateGithubIDPForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create github Id p forbidden response
func (o *CreateGithubIDPForbidden) Code() int {
	return 403
}

func (o *CreateGithubIDPForbidden) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/github][%d] createGithubIdPForbidden  %+v", 403, o.Payload)
}

func (o *CreateGithubIDPForbidden) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/github][%d] createGithubIdPForbidden  %+v", 403, o.Payload)
}

func (o *CreateGithubIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateGithubIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateGithubIDPNotFound creates a CreateGithubIDPNotFound with default headers values
func NewCreateGithubIDPNotFound() *CreateGithubIDPNotFound {
	return &CreateGithubIDPNotFound{}
}

/*
CreateGithubIDPNotFound describes a response with status code 404, with default header values.

Not found
*/
type CreateGithubIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this create github Id p not found response has a 2xx status code
func (o *CreateGithubIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create github Id p not found response has a 3xx status code
func (o *CreateGithubIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create github Id p not found response has a 4xx status code
func (o *CreateGithubIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this create github Id p not found response has a 5xx status code
func (o *CreateGithubIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this create github Id p not found response a status code equal to that given
func (o *CreateGithubIDPNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the create github Id p not found response
func (o *CreateGithubIDPNotFound) Code() int {
	return 404
}

func (o *CreateGithubIDPNotFound) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/github][%d] createGithubIdPNotFound  %+v", 404, o.Payload)
}

func (o *CreateGithubIDPNotFound) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/github][%d] createGithubIdPNotFound  %+v", 404, o.Payload)
}

func (o *CreateGithubIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateGithubIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateGithubIDPUnprocessableEntity creates a CreateGithubIDPUnprocessableEntity with default headers values
func NewCreateGithubIDPUnprocessableEntity() *CreateGithubIDPUnprocessableEntity {
	return &CreateGithubIDPUnprocessableEntity{}
}

/*
CreateGithubIDPUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type CreateGithubIDPUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this create github Id p unprocessable entity response has a 2xx status code
func (o *CreateGithubIDPUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create github Id p unprocessable entity response has a 3xx status code
func (o *CreateGithubIDPUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create github Id p unprocessable entity response has a 4xx status code
func (o *CreateGithubIDPUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this create github Id p unprocessable entity response has a 5xx status code
func (o *CreateGithubIDPUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this create github Id p unprocessable entity response a status code equal to that given
func (o *CreateGithubIDPUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the create github Id p unprocessable entity response
func (o *CreateGithubIDPUnprocessableEntity) Code() int {
	return 422
}

func (o *CreateGithubIDPUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/github][%d] createGithubIdPUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CreateGithubIDPUnprocessableEntity) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/github][%d] createGithubIdPUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CreateGithubIDPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateGithubIDPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateGithubIDPTooManyRequests creates a CreateGithubIDPTooManyRequests with default headers values
func NewCreateGithubIDPTooManyRequests() *CreateGithubIDPTooManyRequests {
	return &CreateGithubIDPTooManyRequests{}
}

/*
CreateGithubIDPTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type CreateGithubIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this create github Id p too many requests response has a 2xx status code
func (o *CreateGithubIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create github Id p too many requests response has a 3xx status code
func (o *CreateGithubIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create github Id p too many requests response has a 4xx status code
func (o *CreateGithubIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create github Id p too many requests response has a 5xx status code
func (o *CreateGithubIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create github Id p too many requests response a status code equal to that given
func (o *CreateGithubIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create github Id p too many requests response
func (o *CreateGithubIDPTooManyRequests) Code() int {
	return 429
}

func (o *CreateGithubIDPTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/github][%d] createGithubIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateGithubIDPTooManyRequests) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/github][%d] createGithubIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateGithubIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateGithubIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
