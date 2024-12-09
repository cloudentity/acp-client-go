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

// CreateAzureB2CIDPReader is a Reader for the CreateAzureB2CIDP structure.
type CreateAzureB2CIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateAzureB2CIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateAzureB2CIDPCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateAzureB2CIDPBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateAzureB2CIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateAzureB2CIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateAzureB2CIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateAzureB2CIDPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateAzureB2CIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /servers/{wid}/idps/azureb2c] createAzureB2CIDP", response, response.Code())
	}
}

// NewCreateAzureB2CIDPCreated creates a CreateAzureB2CIDPCreated with default headers values
func NewCreateAzureB2CIDPCreated() *CreateAzureB2CIDPCreated {
	return &CreateAzureB2CIDPCreated{}
}

/*
CreateAzureB2CIDPCreated describes a response with status code 201, with default header values.

AzureB2CIDP
*/
type CreateAzureB2CIDPCreated struct {
	Payload *models.AzureB2CIDP
}

// IsSuccess returns true when this create azure b2 c Id p created response has a 2xx status code
func (o *CreateAzureB2CIDPCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create azure b2 c Id p created response has a 3xx status code
func (o *CreateAzureB2CIDPCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create azure b2 c Id p created response has a 4xx status code
func (o *CreateAzureB2CIDPCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create azure b2 c Id p created response has a 5xx status code
func (o *CreateAzureB2CIDPCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create azure b2 c Id p created response a status code equal to that given
func (o *CreateAzureB2CIDPCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create azure b2 c Id p created response
func (o *CreateAzureB2CIDPCreated) Code() int {
	return 201
}

func (o *CreateAzureB2CIDPCreated) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/azureb2c][%d] createAzureB2CIdPCreated  %+v", 201, o.Payload)
}

func (o *CreateAzureB2CIDPCreated) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/azureb2c][%d] createAzureB2CIdPCreated  %+v", 201, o.Payload)
}

func (o *CreateAzureB2CIDPCreated) GetPayload() *models.AzureB2CIDP {
	return o.Payload
}

func (o *CreateAzureB2CIDPCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.AzureB2CIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAzureB2CIDPBadRequest creates a CreateAzureB2CIDPBadRequest with default headers values
func NewCreateAzureB2CIDPBadRequest() *CreateAzureB2CIDPBadRequest {
	return &CreateAzureB2CIDPBadRequest{}
}

/*
CreateAzureB2CIDPBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type CreateAzureB2CIDPBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this create azure b2 c Id p bad request response has a 2xx status code
func (o *CreateAzureB2CIDPBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create azure b2 c Id p bad request response has a 3xx status code
func (o *CreateAzureB2CIDPBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create azure b2 c Id p bad request response has a 4xx status code
func (o *CreateAzureB2CIDPBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create azure b2 c Id p bad request response has a 5xx status code
func (o *CreateAzureB2CIDPBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create azure b2 c Id p bad request response a status code equal to that given
func (o *CreateAzureB2CIDPBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create azure b2 c Id p bad request response
func (o *CreateAzureB2CIDPBadRequest) Code() int {
	return 400
}

func (o *CreateAzureB2CIDPBadRequest) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/azureb2c][%d] createAzureB2CIdPBadRequest  %+v", 400, o.Payload)
}

func (o *CreateAzureB2CIDPBadRequest) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/azureb2c][%d] createAzureB2CIdPBadRequest  %+v", 400, o.Payload)
}

func (o *CreateAzureB2CIDPBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAzureB2CIDPBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAzureB2CIDPUnauthorized creates a CreateAzureB2CIDPUnauthorized with default headers values
func NewCreateAzureB2CIDPUnauthorized() *CreateAzureB2CIDPUnauthorized {
	return &CreateAzureB2CIDPUnauthorized{}
}

/*
CreateAzureB2CIDPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CreateAzureB2CIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this create azure b2 c Id p unauthorized response has a 2xx status code
func (o *CreateAzureB2CIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create azure b2 c Id p unauthorized response has a 3xx status code
func (o *CreateAzureB2CIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create azure b2 c Id p unauthorized response has a 4xx status code
func (o *CreateAzureB2CIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create azure b2 c Id p unauthorized response has a 5xx status code
func (o *CreateAzureB2CIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create azure b2 c Id p unauthorized response a status code equal to that given
func (o *CreateAzureB2CIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the create azure b2 c Id p unauthorized response
func (o *CreateAzureB2CIDPUnauthorized) Code() int {
	return 401
}

func (o *CreateAzureB2CIDPUnauthorized) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/azureb2c][%d] createAzureB2CIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateAzureB2CIDPUnauthorized) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/azureb2c][%d] createAzureB2CIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateAzureB2CIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAzureB2CIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAzureB2CIDPForbidden creates a CreateAzureB2CIDPForbidden with default headers values
func NewCreateAzureB2CIDPForbidden() *CreateAzureB2CIDPForbidden {
	return &CreateAzureB2CIDPForbidden{}
}

/*
CreateAzureB2CIDPForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateAzureB2CIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this create azure b2 c Id p forbidden response has a 2xx status code
func (o *CreateAzureB2CIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create azure b2 c Id p forbidden response has a 3xx status code
func (o *CreateAzureB2CIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create azure b2 c Id p forbidden response has a 4xx status code
func (o *CreateAzureB2CIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create azure b2 c Id p forbidden response has a 5xx status code
func (o *CreateAzureB2CIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create azure b2 c Id p forbidden response a status code equal to that given
func (o *CreateAzureB2CIDPForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create azure b2 c Id p forbidden response
func (o *CreateAzureB2CIDPForbidden) Code() int {
	return 403
}

func (o *CreateAzureB2CIDPForbidden) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/azureb2c][%d] createAzureB2CIdPForbidden  %+v", 403, o.Payload)
}

func (o *CreateAzureB2CIDPForbidden) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/azureb2c][%d] createAzureB2CIdPForbidden  %+v", 403, o.Payload)
}

func (o *CreateAzureB2CIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAzureB2CIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAzureB2CIDPNotFound creates a CreateAzureB2CIDPNotFound with default headers values
func NewCreateAzureB2CIDPNotFound() *CreateAzureB2CIDPNotFound {
	return &CreateAzureB2CIDPNotFound{}
}

/*
CreateAzureB2CIDPNotFound describes a response with status code 404, with default header values.

Not found
*/
type CreateAzureB2CIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this create azure b2 c Id p not found response has a 2xx status code
func (o *CreateAzureB2CIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create azure b2 c Id p not found response has a 3xx status code
func (o *CreateAzureB2CIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create azure b2 c Id p not found response has a 4xx status code
func (o *CreateAzureB2CIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this create azure b2 c Id p not found response has a 5xx status code
func (o *CreateAzureB2CIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this create azure b2 c Id p not found response a status code equal to that given
func (o *CreateAzureB2CIDPNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the create azure b2 c Id p not found response
func (o *CreateAzureB2CIDPNotFound) Code() int {
	return 404
}

func (o *CreateAzureB2CIDPNotFound) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/azureb2c][%d] createAzureB2CIdPNotFound  %+v", 404, o.Payload)
}

func (o *CreateAzureB2CIDPNotFound) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/azureb2c][%d] createAzureB2CIdPNotFound  %+v", 404, o.Payload)
}

func (o *CreateAzureB2CIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAzureB2CIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAzureB2CIDPUnprocessableEntity creates a CreateAzureB2CIDPUnprocessableEntity with default headers values
func NewCreateAzureB2CIDPUnprocessableEntity() *CreateAzureB2CIDPUnprocessableEntity {
	return &CreateAzureB2CIDPUnprocessableEntity{}
}

/*
CreateAzureB2CIDPUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type CreateAzureB2CIDPUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this create azure b2 c Id p unprocessable entity response has a 2xx status code
func (o *CreateAzureB2CIDPUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create azure b2 c Id p unprocessable entity response has a 3xx status code
func (o *CreateAzureB2CIDPUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create azure b2 c Id p unprocessable entity response has a 4xx status code
func (o *CreateAzureB2CIDPUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this create azure b2 c Id p unprocessable entity response has a 5xx status code
func (o *CreateAzureB2CIDPUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this create azure b2 c Id p unprocessable entity response a status code equal to that given
func (o *CreateAzureB2CIDPUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the create azure b2 c Id p unprocessable entity response
func (o *CreateAzureB2CIDPUnprocessableEntity) Code() int {
	return 422
}

func (o *CreateAzureB2CIDPUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/azureb2c][%d] createAzureB2CIdPUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CreateAzureB2CIDPUnprocessableEntity) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/azureb2c][%d] createAzureB2CIdPUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CreateAzureB2CIDPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAzureB2CIDPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAzureB2CIDPTooManyRequests creates a CreateAzureB2CIDPTooManyRequests with default headers values
func NewCreateAzureB2CIDPTooManyRequests() *CreateAzureB2CIDPTooManyRequests {
	return &CreateAzureB2CIDPTooManyRequests{}
}

/*
CreateAzureB2CIDPTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type CreateAzureB2CIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this create azure b2 c Id p too many requests response has a 2xx status code
func (o *CreateAzureB2CIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create azure b2 c Id p too many requests response has a 3xx status code
func (o *CreateAzureB2CIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create azure b2 c Id p too many requests response has a 4xx status code
func (o *CreateAzureB2CIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create azure b2 c Id p too many requests response has a 5xx status code
func (o *CreateAzureB2CIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create azure b2 c Id p too many requests response a status code equal to that given
func (o *CreateAzureB2CIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create azure b2 c Id p too many requests response
func (o *CreateAzureB2CIDPTooManyRequests) Code() int {
	return 429
}

func (o *CreateAzureB2CIDPTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/azureb2c][%d] createAzureB2CIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateAzureB2CIDPTooManyRequests) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/azureb2c][%d] createAzureB2CIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateAzureB2CIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAzureB2CIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
