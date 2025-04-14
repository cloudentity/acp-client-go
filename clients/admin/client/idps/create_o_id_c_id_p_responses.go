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

// CreateOIDCIDPReader is a Reader for the CreateOIDCIDP structure.
type CreateOIDCIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateOIDCIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateOIDCIDPCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateOIDCIDPBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateOIDCIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateOIDCIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateOIDCIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateOIDCIDPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateOIDCIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /servers/{wid}/idps/oidc] createOIDCIDP", response, response.Code())
	}
}

// NewCreateOIDCIDPCreated creates a CreateOIDCIDPCreated with default headers values
func NewCreateOIDCIDPCreated() *CreateOIDCIDPCreated {
	return &CreateOIDCIDPCreated{}
}

/*
CreateOIDCIDPCreated describes a response with status code 201, with default header values.

OIDCIDP
*/
type CreateOIDCIDPCreated struct {
	Payload *models.OIDCIDP
}

// IsSuccess returns true when this create o Id c Id p created response has a 2xx status code
func (o *CreateOIDCIDPCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create o Id c Id p created response has a 3xx status code
func (o *CreateOIDCIDPCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create o Id c Id p created response has a 4xx status code
func (o *CreateOIDCIDPCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create o Id c Id p created response has a 5xx status code
func (o *CreateOIDCIDPCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create o Id c Id p created response a status code equal to that given
func (o *CreateOIDCIDPCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create o Id c Id p created response
func (o *CreateOIDCIDPCreated) Code() int {
	return 201
}

func (o *CreateOIDCIDPCreated) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/oidc][%d] createOIdCIdPCreated  %+v", 201, o.Payload)
}

func (o *CreateOIDCIDPCreated) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/oidc][%d] createOIdCIdPCreated  %+v", 201, o.Payload)
}

func (o *CreateOIDCIDPCreated) GetPayload() *models.OIDCIDP {
	return o.Payload
}

func (o *CreateOIDCIDPCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OIDCIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateOIDCIDPBadRequest creates a CreateOIDCIDPBadRequest with default headers values
func NewCreateOIDCIDPBadRequest() *CreateOIDCIDPBadRequest {
	return &CreateOIDCIDPBadRequest{}
}

/*
CreateOIDCIDPBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type CreateOIDCIDPBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this create o Id c Id p bad request response has a 2xx status code
func (o *CreateOIDCIDPBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create o Id c Id p bad request response has a 3xx status code
func (o *CreateOIDCIDPBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create o Id c Id p bad request response has a 4xx status code
func (o *CreateOIDCIDPBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create o Id c Id p bad request response has a 5xx status code
func (o *CreateOIDCIDPBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create o Id c Id p bad request response a status code equal to that given
func (o *CreateOIDCIDPBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create o Id c Id p bad request response
func (o *CreateOIDCIDPBadRequest) Code() int {
	return 400
}

func (o *CreateOIDCIDPBadRequest) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/oidc][%d] createOIdCIdPBadRequest  %+v", 400, o.Payload)
}

func (o *CreateOIDCIDPBadRequest) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/oidc][%d] createOIdCIdPBadRequest  %+v", 400, o.Payload)
}

func (o *CreateOIDCIDPBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateOIDCIDPBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateOIDCIDPUnauthorized creates a CreateOIDCIDPUnauthorized with default headers values
func NewCreateOIDCIDPUnauthorized() *CreateOIDCIDPUnauthorized {
	return &CreateOIDCIDPUnauthorized{}
}

/*
CreateOIDCIDPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CreateOIDCIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this create o Id c Id p unauthorized response has a 2xx status code
func (o *CreateOIDCIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create o Id c Id p unauthorized response has a 3xx status code
func (o *CreateOIDCIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create o Id c Id p unauthorized response has a 4xx status code
func (o *CreateOIDCIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create o Id c Id p unauthorized response has a 5xx status code
func (o *CreateOIDCIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create o Id c Id p unauthorized response a status code equal to that given
func (o *CreateOIDCIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the create o Id c Id p unauthorized response
func (o *CreateOIDCIDPUnauthorized) Code() int {
	return 401
}

func (o *CreateOIDCIDPUnauthorized) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/oidc][%d] createOIdCIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateOIDCIDPUnauthorized) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/oidc][%d] createOIdCIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateOIDCIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateOIDCIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateOIDCIDPForbidden creates a CreateOIDCIDPForbidden with default headers values
func NewCreateOIDCIDPForbidden() *CreateOIDCIDPForbidden {
	return &CreateOIDCIDPForbidden{}
}

/*
CreateOIDCIDPForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateOIDCIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this create o Id c Id p forbidden response has a 2xx status code
func (o *CreateOIDCIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create o Id c Id p forbidden response has a 3xx status code
func (o *CreateOIDCIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create o Id c Id p forbidden response has a 4xx status code
func (o *CreateOIDCIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create o Id c Id p forbidden response has a 5xx status code
func (o *CreateOIDCIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create o Id c Id p forbidden response a status code equal to that given
func (o *CreateOIDCIDPForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create o Id c Id p forbidden response
func (o *CreateOIDCIDPForbidden) Code() int {
	return 403
}

func (o *CreateOIDCIDPForbidden) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/oidc][%d] createOIdCIdPForbidden  %+v", 403, o.Payload)
}

func (o *CreateOIDCIDPForbidden) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/oidc][%d] createOIdCIdPForbidden  %+v", 403, o.Payload)
}

func (o *CreateOIDCIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateOIDCIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateOIDCIDPNotFound creates a CreateOIDCIDPNotFound with default headers values
func NewCreateOIDCIDPNotFound() *CreateOIDCIDPNotFound {
	return &CreateOIDCIDPNotFound{}
}

/*
CreateOIDCIDPNotFound describes a response with status code 404, with default header values.

Not found
*/
type CreateOIDCIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this create o Id c Id p not found response has a 2xx status code
func (o *CreateOIDCIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create o Id c Id p not found response has a 3xx status code
func (o *CreateOIDCIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create o Id c Id p not found response has a 4xx status code
func (o *CreateOIDCIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this create o Id c Id p not found response has a 5xx status code
func (o *CreateOIDCIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this create o Id c Id p not found response a status code equal to that given
func (o *CreateOIDCIDPNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the create o Id c Id p not found response
func (o *CreateOIDCIDPNotFound) Code() int {
	return 404
}

func (o *CreateOIDCIDPNotFound) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/oidc][%d] createOIdCIdPNotFound  %+v", 404, o.Payload)
}

func (o *CreateOIDCIDPNotFound) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/oidc][%d] createOIdCIdPNotFound  %+v", 404, o.Payload)
}

func (o *CreateOIDCIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateOIDCIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateOIDCIDPUnprocessableEntity creates a CreateOIDCIDPUnprocessableEntity with default headers values
func NewCreateOIDCIDPUnprocessableEntity() *CreateOIDCIDPUnprocessableEntity {
	return &CreateOIDCIDPUnprocessableEntity{}
}

/*
CreateOIDCIDPUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type CreateOIDCIDPUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this create o Id c Id p unprocessable entity response has a 2xx status code
func (o *CreateOIDCIDPUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create o Id c Id p unprocessable entity response has a 3xx status code
func (o *CreateOIDCIDPUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create o Id c Id p unprocessable entity response has a 4xx status code
func (o *CreateOIDCIDPUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this create o Id c Id p unprocessable entity response has a 5xx status code
func (o *CreateOIDCIDPUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this create o Id c Id p unprocessable entity response a status code equal to that given
func (o *CreateOIDCIDPUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the create o Id c Id p unprocessable entity response
func (o *CreateOIDCIDPUnprocessableEntity) Code() int {
	return 422
}

func (o *CreateOIDCIDPUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/oidc][%d] createOIdCIdPUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CreateOIDCIDPUnprocessableEntity) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/oidc][%d] createOIdCIdPUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CreateOIDCIDPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateOIDCIDPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateOIDCIDPTooManyRequests creates a CreateOIDCIDPTooManyRequests with default headers values
func NewCreateOIDCIDPTooManyRequests() *CreateOIDCIDPTooManyRequests {
	return &CreateOIDCIDPTooManyRequests{}
}

/*
CreateOIDCIDPTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type CreateOIDCIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this create o Id c Id p too many requests response has a 2xx status code
func (o *CreateOIDCIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create o Id c Id p too many requests response has a 3xx status code
func (o *CreateOIDCIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create o Id c Id p too many requests response has a 4xx status code
func (o *CreateOIDCIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create o Id c Id p too many requests response has a 5xx status code
func (o *CreateOIDCIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create o Id c Id p too many requests response a status code equal to that given
func (o *CreateOIDCIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create o Id c Id p too many requests response
func (o *CreateOIDCIDPTooManyRequests) Code() int {
	return 429
}

func (o *CreateOIDCIDPTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/oidc][%d] createOIdCIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateOIDCIDPTooManyRequests) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/oidc][%d] createOIdCIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateOIDCIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateOIDCIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
