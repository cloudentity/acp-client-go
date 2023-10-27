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

// CreateWorkspaceIDPReader is a Reader for the CreateWorkspaceIDP structure.
type CreateWorkspaceIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateWorkspaceIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateWorkspaceIDPCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateWorkspaceIDPBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateWorkspaceIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateWorkspaceIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateWorkspaceIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateWorkspaceIDPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateWorkspaceIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /servers/{wid}/idps/workspace] createWorkspaceIDP", response, response.Code())
	}
}

// NewCreateWorkspaceIDPCreated creates a CreateWorkspaceIDPCreated with default headers values
func NewCreateWorkspaceIDPCreated() *CreateWorkspaceIDPCreated {
	return &CreateWorkspaceIDPCreated{}
}

/*
CreateWorkspaceIDPCreated describes a response with status code 201, with default header values.

WorkspaceIDP
*/
type CreateWorkspaceIDPCreated struct {
	Payload *models.WorkspaceIDP
}

// IsSuccess returns true when this create workspace Id p created response has a 2xx status code
func (o *CreateWorkspaceIDPCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create workspace Id p created response has a 3xx status code
func (o *CreateWorkspaceIDPCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create workspace Id p created response has a 4xx status code
func (o *CreateWorkspaceIDPCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create workspace Id p created response has a 5xx status code
func (o *CreateWorkspaceIDPCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create workspace Id p created response a status code equal to that given
func (o *CreateWorkspaceIDPCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create workspace Id p created response
func (o *CreateWorkspaceIDPCreated) Code() int {
	return 201
}

func (o *CreateWorkspaceIDPCreated) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/workspace][%d] createWorkspaceIdPCreated  %+v", 201, o.Payload)
}

func (o *CreateWorkspaceIDPCreated) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/workspace][%d] createWorkspaceIdPCreated  %+v", 201, o.Payload)
}

func (o *CreateWorkspaceIDPCreated) GetPayload() *models.WorkspaceIDP {
	return o.Payload
}

func (o *CreateWorkspaceIDPCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.WorkspaceIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateWorkspaceIDPBadRequest creates a CreateWorkspaceIDPBadRequest with default headers values
func NewCreateWorkspaceIDPBadRequest() *CreateWorkspaceIDPBadRequest {
	return &CreateWorkspaceIDPBadRequest{}
}

/*
CreateWorkspaceIDPBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type CreateWorkspaceIDPBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this create workspace Id p bad request response has a 2xx status code
func (o *CreateWorkspaceIDPBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create workspace Id p bad request response has a 3xx status code
func (o *CreateWorkspaceIDPBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create workspace Id p bad request response has a 4xx status code
func (o *CreateWorkspaceIDPBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create workspace Id p bad request response has a 5xx status code
func (o *CreateWorkspaceIDPBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create workspace Id p bad request response a status code equal to that given
func (o *CreateWorkspaceIDPBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create workspace Id p bad request response
func (o *CreateWorkspaceIDPBadRequest) Code() int {
	return 400
}

func (o *CreateWorkspaceIDPBadRequest) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/workspace][%d] createWorkspaceIdPBadRequest  %+v", 400, o.Payload)
}

func (o *CreateWorkspaceIDPBadRequest) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/workspace][%d] createWorkspaceIdPBadRequest  %+v", 400, o.Payload)
}

func (o *CreateWorkspaceIDPBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateWorkspaceIDPBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateWorkspaceIDPUnauthorized creates a CreateWorkspaceIDPUnauthorized with default headers values
func NewCreateWorkspaceIDPUnauthorized() *CreateWorkspaceIDPUnauthorized {
	return &CreateWorkspaceIDPUnauthorized{}
}

/*
CreateWorkspaceIDPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CreateWorkspaceIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this create workspace Id p unauthorized response has a 2xx status code
func (o *CreateWorkspaceIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create workspace Id p unauthorized response has a 3xx status code
func (o *CreateWorkspaceIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create workspace Id p unauthorized response has a 4xx status code
func (o *CreateWorkspaceIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create workspace Id p unauthorized response has a 5xx status code
func (o *CreateWorkspaceIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create workspace Id p unauthorized response a status code equal to that given
func (o *CreateWorkspaceIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the create workspace Id p unauthorized response
func (o *CreateWorkspaceIDPUnauthorized) Code() int {
	return 401
}

func (o *CreateWorkspaceIDPUnauthorized) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/workspace][%d] createWorkspaceIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateWorkspaceIDPUnauthorized) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/workspace][%d] createWorkspaceIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateWorkspaceIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateWorkspaceIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateWorkspaceIDPForbidden creates a CreateWorkspaceIDPForbidden with default headers values
func NewCreateWorkspaceIDPForbidden() *CreateWorkspaceIDPForbidden {
	return &CreateWorkspaceIDPForbidden{}
}

/*
CreateWorkspaceIDPForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateWorkspaceIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this create workspace Id p forbidden response has a 2xx status code
func (o *CreateWorkspaceIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create workspace Id p forbidden response has a 3xx status code
func (o *CreateWorkspaceIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create workspace Id p forbidden response has a 4xx status code
func (o *CreateWorkspaceIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create workspace Id p forbidden response has a 5xx status code
func (o *CreateWorkspaceIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create workspace Id p forbidden response a status code equal to that given
func (o *CreateWorkspaceIDPForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create workspace Id p forbidden response
func (o *CreateWorkspaceIDPForbidden) Code() int {
	return 403
}

func (o *CreateWorkspaceIDPForbidden) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/workspace][%d] createWorkspaceIdPForbidden  %+v", 403, o.Payload)
}

func (o *CreateWorkspaceIDPForbidden) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/workspace][%d] createWorkspaceIdPForbidden  %+v", 403, o.Payload)
}

func (o *CreateWorkspaceIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateWorkspaceIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateWorkspaceIDPNotFound creates a CreateWorkspaceIDPNotFound with default headers values
func NewCreateWorkspaceIDPNotFound() *CreateWorkspaceIDPNotFound {
	return &CreateWorkspaceIDPNotFound{}
}

/*
CreateWorkspaceIDPNotFound describes a response with status code 404, with default header values.

Not found
*/
type CreateWorkspaceIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this create workspace Id p not found response has a 2xx status code
func (o *CreateWorkspaceIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create workspace Id p not found response has a 3xx status code
func (o *CreateWorkspaceIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create workspace Id p not found response has a 4xx status code
func (o *CreateWorkspaceIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this create workspace Id p not found response has a 5xx status code
func (o *CreateWorkspaceIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this create workspace Id p not found response a status code equal to that given
func (o *CreateWorkspaceIDPNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the create workspace Id p not found response
func (o *CreateWorkspaceIDPNotFound) Code() int {
	return 404
}

func (o *CreateWorkspaceIDPNotFound) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/workspace][%d] createWorkspaceIdPNotFound  %+v", 404, o.Payload)
}

func (o *CreateWorkspaceIDPNotFound) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/workspace][%d] createWorkspaceIdPNotFound  %+v", 404, o.Payload)
}

func (o *CreateWorkspaceIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateWorkspaceIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateWorkspaceIDPUnprocessableEntity creates a CreateWorkspaceIDPUnprocessableEntity with default headers values
func NewCreateWorkspaceIDPUnprocessableEntity() *CreateWorkspaceIDPUnprocessableEntity {
	return &CreateWorkspaceIDPUnprocessableEntity{}
}

/*
CreateWorkspaceIDPUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type CreateWorkspaceIDPUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this create workspace Id p unprocessable entity response has a 2xx status code
func (o *CreateWorkspaceIDPUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create workspace Id p unprocessable entity response has a 3xx status code
func (o *CreateWorkspaceIDPUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create workspace Id p unprocessable entity response has a 4xx status code
func (o *CreateWorkspaceIDPUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this create workspace Id p unprocessable entity response has a 5xx status code
func (o *CreateWorkspaceIDPUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this create workspace Id p unprocessable entity response a status code equal to that given
func (o *CreateWorkspaceIDPUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the create workspace Id p unprocessable entity response
func (o *CreateWorkspaceIDPUnprocessableEntity) Code() int {
	return 422
}

func (o *CreateWorkspaceIDPUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/workspace][%d] createWorkspaceIdPUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CreateWorkspaceIDPUnprocessableEntity) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/workspace][%d] createWorkspaceIdPUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CreateWorkspaceIDPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateWorkspaceIDPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateWorkspaceIDPTooManyRequests creates a CreateWorkspaceIDPTooManyRequests with default headers values
func NewCreateWorkspaceIDPTooManyRequests() *CreateWorkspaceIDPTooManyRequests {
	return &CreateWorkspaceIDPTooManyRequests{}
}

/*
CreateWorkspaceIDPTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type CreateWorkspaceIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this create workspace Id p too many requests response has a 2xx status code
func (o *CreateWorkspaceIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create workspace Id p too many requests response has a 3xx status code
func (o *CreateWorkspaceIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create workspace Id p too many requests response has a 4xx status code
func (o *CreateWorkspaceIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create workspace Id p too many requests response has a 5xx status code
func (o *CreateWorkspaceIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create workspace Id p too many requests response a status code equal to that given
func (o *CreateWorkspaceIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create workspace Id p too many requests response
func (o *CreateWorkspaceIDPTooManyRequests) Code() int {
	return 429
}

func (o *CreateWorkspaceIDPTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/workspace][%d] createWorkspaceIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateWorkspaceIDPTooManyRequests) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/workspace][%d] createWorkspaceIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateWorkspaceIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateWorkspaceIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}