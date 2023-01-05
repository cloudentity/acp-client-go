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

// CreateCognitoIDPReader is a Reader for the CreateCognitoIDP structure.
type CreateCognitoIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateCognitoIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateCognitoIDPCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateCognitoIDPBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateCognitoIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateCognitoIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateCognitoIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateCognitoIDPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateCognitoIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewCreateCognitoIDPCreated creates a CreateCognitoIDPCreated with default headers values
func NewCreateCognitoIDPCreated() *CreateCognitoIDPCreated {
	return &CreateCognitoIDPCreated{}
}

/*
CreateCognitoIDPCreated describes a response with status code 201, with default header values.

CognitoIDP
*/
type CreateCognitoIDPCreated struct {
	Payload *models.CognitoIDP
}

// IsSuccess returns true when this create cognito Id p created response has a 2xx status code
func (o *CreateCognitoIDPCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create cognito Id p created response has a 3xx status code
func (o *CreateCognitoIDPCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create cognito Id p created response has a 4xx status code
func (o *CreateCognitoIDPCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create cognito Id p created response has a 5xx status code
func (o *CreateCognitoIDPCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create cognito Id p created response a status code equal to that given
func (o *CreateCognitoIDPCreated) IsCode(code int) bool {
	return code == 201
}

func (o *CreateCognitoIDPCreated) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/cognito][%d] createCognitoIdPCreated  %+v", 201, o.Payload)
}

func (o *CreateCognitoIDPCreated) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/cognito][%d] createCognitoIdPCreated  %+v", 201, o.Payload)
}

func (o *CreateCognitoIDPCreated) GetPayload() *models.CognitoIDP {
	return o.Payload
}

func (o *CreateCognitoIDPCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.CognitoIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateCognitoIDPBadRequest creates a CreateCognitoIDPBadRequest with default headers values
func NewCreateCognitoIDPBadRequest() *CreateCognitoIDPBadRequest {
	return &CreateCognitoIDPBadRequest{}
}

/*
CreateCognitoIDPBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type CreateCognitoIDPBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this create cognito Id p bad request response has a 2xx status code
func (o *CreateCognitoIDPBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create cognito Id p bad request response has a 3xx status code
func (o *CreateCognitoIDPBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create cognito Id p bad request response has a 4xx status code
func (o *CreateCognitoIDPBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create cognito Id p bad request response has a 5xx status code
func (o *CreateCognitoIDPBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create cognito Id p bad request response a status code equal to that given
func (o *CreateCognitoIDPBadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *CreateCognitoIDPBadRequest) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/cognito][%d] createCognitoIdPBadRequest  %+v", 400, o.Payload)
}

func (o *CreateCognitoIDPBadRequest) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/cognito][%d] createCognitoIdPBadRequest  %+v", 400, o.Payload)
}

func (o *CreateCognitoIDPBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateCognitoIDPBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateCognitoIDPUnauthorized creates a CreateCognitoIDPUnauthorized with default headers values
func NewCreateCognitoIDPUnauthorized() *CreateCognitoIDPUnauthorized {
	return &CreateCognitoIDPUnauthorized{}
}

/*
CreateCognitoIDPUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type CreateCognitoIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this create cognito Id p unauthorized response has a 2xx status code
func (o *CreateCognitoIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create cognito Id p unauthorized response has a 3xx status code
func (o *CreateCognitoIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create cognito Id p unauthorized response has a 4xx status code
func (o *CreateCognitoIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create cognito Id p unauthorized response has a 5xx status code
func (o *CreateCognitoIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create cognito Id p unauthorized response a status code equal to that given
func (o *CreateCognitoIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *CreateCognitoIDPUnauthorized) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/cognito][%d] createCognitoIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateCognitoIDPUnauthorized) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/cognito][%d] createCognitoIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateCognitoIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateCognitoIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateCognitoIDPForbidden creates a CreateCognitoIDPForbidden with default headers values
func NewCreateCognitoIDPForbidden() *CreateCognitoIDPForbidden {
	return &CreateCognitoIDPForbidden{}
}

/*
CreateCognitoIDPForbidden describes a response with status code 403, with default header values.

HttpError
*/
type CreateCognitoIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this create cognito Id p forbidden response has a 2xx status code
func (o *CreateCognitoIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create cognito Id p forbidden response has a 3xx status code
func (o *CreateCognitoIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create cognito Id p forbidden response has a 4xx status code
func (o *CreateCognitoIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create cognito Id p forbidden response has a 5xx status code
func (o *CreateCognitoIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create cognito Id p forbidden response a status code equal to that given
func (o *CreateCognitoIDPForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *CreateCognitoIDPForbidden) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/cognito][%d] createCognitoIdPForbidden  %+v", 403, o.Payload)
}

func (o *CreateCognitoIDPForbidden) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/cognito][%d] createCognitoIdPForbidden  %+v", 403, o.Payload)
}

func (o *CreateCognitoIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateCognitoIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateCognitoIDPNotFound creates a CreateCognitoIDPNotFound with default headers values
func NewCreateCognitoIDPNotFound() *CreateCognitoIDPNotFound {
	return &CreateCognitoIDPNotFound{}
}

/*
CreateCognitoIDPNotFound describes a response with status code 404, with default header values.

HttpError
*/
type CreateCognitoIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this create cognito Id p not found response has a 2xx status code
func (o *CreateCognitoIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create cognito Id p not found response has a 3xx status code
func (o *CreateCognitoIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create cognito Id p not found response has a 4xx status code
func (o *CreateCognitoIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this create cognito Id p not found response has a 5xx status code
func (o *CreateCognitoIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this create cognito Id p not found response a status code equal to that given
func (o *CreateCognitoIDPNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *CreateCognitoIDPNotFound) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/cognito][%d] createCognitoIdPNotFound  %+v", 404, o.Payload)
}

func (o *CreateCognitoIDPNotFound) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/cognito][%d] createCognitoIdPNotFound  %+v", 404, o.Payload)
}

func (o *CreateCognitoIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateCognitoIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateCognitoIDPUnprocessableEntity creates a CreateCognitoIDPUnprocessableEntity with default headers values
func NewCreateCognitoIDPUnprocessableEntity() *CreateCognitoIDPUnprocessableEntity {
	return &CreateCognitoIDPUnprocessableEntity{}
}

/*
CreateCognitoIDPUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type CreateCognitoIDPUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this create cognito Id p unprocessable entity response has a 2xx status code
func (o *CreateCognitoIDPUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create cognito Id p unprocessable entity response has a 3xx status code
func (o *CreateCognitoIDPUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create cognito Id p unprocessable entity response has a 4xx status code
func (o *CreateCognitoIDPUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this create cognito Id p unprocessable entity response has a 5xx status code
func (o *CreateCognitoIDPUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this create cognito Id p unprocessable entity response a status code equal to that given
func (o *CreateCognitoIDPUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

func (o *CreateCognitoIDPUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/cognito][%d] createCognitoIdPUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CreateCognitoIDPUnprocessableEntity) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/cognito][%d] createCognitoIdPUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CreateCognitoIDPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateCognitoIDPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateCognitoIDPTooManyRequests creates a CreateCognitoIDPTooManyRequests with default headers values
func NewCreateCognitoIDPTooManyRequests() *CreateCognitoIDPTooManyRequests {
	return &CreateCognitoIDPTooManyRequests{}
}

/*
CreateCognitoIDPTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type CreateCognitoIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this create cognito Id p too many requests response has a 2xx status code
func (o *CreateCognitoIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create cognito Id p too many requests response has a 3xx status code
func (o *CreateCognitoIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create cognito Id p too many requests response has a 4xx status code
func (o *CreateCognitoIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create cognito Id p too many requests response has a 5xx status code
func (o *CreateCognitoIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create cognito Id p too many requests response a status code equal to that given
func (o *CreateCognitoIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *CreateCognitoIDPTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/cognito][%d] createCognitoIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateCognitoIDPTooManyRequests) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/cognito][%d] createCognitoIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateCognitoIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateCognitoIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
