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

// CreateGoogleIDPReader is a Reader for the CreateGoogleIDP structure.
type CreateGoogleIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateGoogleIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateGoogleIDPCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateGoogleIDPBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateGoogleIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateGoogleIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateGoogleIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateGoogleIDPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateGoogleIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /servers/{wid}/idps/google] createGoogleIDP", response, response.Code())
	}
}

// NewCreateGoogleIDPCreated creates a CreateGoogleIDPCreated with default headers values
func NewCreateGoogleIDPCreated() *CreateGoogleIDPCreated {
	return &CreateGoogleIDPCreated{}
}

/*
CreateGoogleIDPCreated describes a response with status code 201, with default header values.

GoogleIDP
*/
type CreateGoogleIDPCreated struct {
	Payload *models.GoogleIDP
}

// IsSuccess returns true when this create google Id p created response has a 2xx status code
func (o *CreateGoogleIDPCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create google Id p created response has a 3xx status code
func (o *CreateGoogleIDPCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create google Id p created response has a 4xx status code
func (o *CreateGoogleIDPCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create google Id p created response has a 5xx status code
func (o *CreateGoogleIDPCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create google Id p created response a status code equal to that given
func (o *CreateGoogleIDPCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create google Id p created response
func (o *CreateGoogleIDPCreated) Code() int {
	return 201
}

func (o *CreateGoogleIDPCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/google][%d] createGoogleIdPCreated %s", 201, payload)
}

func (o *CreateGoogleIDPCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/google][%d] createGoogleIdPCreated %s", 201, payload)
}

func (o *CreateGoogleIDPCreated) GetPayload() *models.GoogleIDP {
	return o.Payload
}

func (o *CreateGoogleIDPCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GoogleIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateGoogleIDPBadRequest creates a CreateGoogleIDPBadRequest with default headers values
func NewCreateGoogleIDPBadRequest() *CreateGoogleIDPBadRequest {
	return &CreateGoogleIDPBadRequest{}
}

/*
CreateGoogleIDPBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type CreateGoogleIDPBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this create google Id p bad request response has a 2xx status code
func (o *CreateGoogleIDPBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create google Id p bad request response has a 3xx status code
func (o *CreateGoogleIDPBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create google Id p bad request response has a 4xx status code
func (o *CreateGoogleIDPBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create google Id p bad request response has a 5xx status code
func (o *CreateGoogleIDPBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create google Id p bad request response a status code equal to that given
func (o *CreateGoogleIDPBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create google Id p bad request response
func (o *CreateGoogleIDPBadRequest) Code() int {
	return 400
}

func (o *CreateGoogleIDPBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/google][%d] createGoogleIdPBadRequest %s", 400, payload)
}

func (o *CreateGoogleIDPBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/google][%d] createGoogleIdPBadRequest %s", 400, payload)
}

func (o *CreateGoogleIDPBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateGoogleIDPBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateGoogleIDPUnauthorized creates a CreateGoogleIDPUnauthorized with default headers values
func NewCreateGoogleIDPUnauthorized() *CreateGoogleIDPUnauthorized {
	return &CreateGoogleIDPUnauthorized{}
}

/*
CreateGoogleIDPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CreateGoogleIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this create google Id p unauthorized response has a 2xx status code
func (o *CreateGoogleIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create google Id p unauthorized response has a 3xx status code
func (o *CreateGoogleIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create google Id p unauthorized response has a 4xx status code
func (o *CreateGoogleIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create google Id p unauthorized response has a 5xx status code
func (o *CreateGoogleIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create google Id p unauthorized response a status code equal to that given
func (o *CreateGoogleIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the create google Id p unauthorized response
func (o *CreateGoogleIDPUnauthorized) Code() int {
	return 401
}

func (o *CreateGoogleIDPUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/google][%d] createGoogleIdPUnauthorized %s", 401, payload)
}

func (o *CreateGoogleIDPUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/google][%d] createGoogleIdPUnauthorized %s", 401, payload)
}

func (o *CreateGoogleIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateGoogleIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateGoogleIDPForbidden creates a CreateGoogleIDPForbidden with default headers values
func NewCreateGoogleIDPForbidden() *CreateGoogleIDPForbidden {
	return &CreateGoogleIDPForbidden{}
}

/*
CreateGoogleIDPForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateGoogleIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this create google Id p forbidden response has a 2xx status code
func (o *CreateGoogleIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create google Id p forbidden response has a 3xx status code
func (o *CreateGoogleIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create google Id p forbidden response has a 4xx status code
func (o *CreateGoogleIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create google Id p forbidden response has a 5xx status code
func (o *CreateGoogleIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create google Id p forbidden response a status code equal to that given
func (o *CreateGoogleIDPForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create google Id p forbidden response
func (o *CreateGoogleIDPForbidden) Code() int {
	return 403
}

func (o *CreateGoogleIDPForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/google][%d] createGoogleIdPForbidden %s", 403, payload)
}

func (o *CreateGoogleIDPForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/google][%d] createGoogleIdPForbidden %s", 403, payload)
}

func (o *CreateGoogleIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateGoogleIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateGoogleIDPNotFound creates a CreateGoogleIDPNotFound with default headers values
func NewCreateGoogleIDPNotFound() *CreateGoogleIDPNotFound {
	return &CreateGoogleIDPNotFound{}
}

/*
CreateGoogleIDPNotFound describes a response with status code 404, with default header values.

Not found
*/
type CreateGoogleIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this create google Id p not found response has a 2xx status code
func (o *CreateGoogleIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create google Id p not found response has a 3xx status code
func (o *CreateGoogleIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create google Id p not found response has a 4xx status code
func (o *CreateGoogleIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this create google Id p not found response has a 5xx status code
func (o *CreateGoogleIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this create google Id p not found response a status code equal to that given
func (o *CreateGoogleIDPNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the create google Id p not found response
func (o *CreateGoogleIDPNotFound) Code() int {
	return 404
}

func (o *CreateGoogleIDPNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/google][%d] createGoogleIdPNotFound %s", 404, payload)
}

func (o *CreateGoogleIDPNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/google][%d] createGoogleIdPNotFound %s", 404, payload)
}

func (o *CreateGoogleIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateGoogleIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateGoogleIDPUnprocessableEntity creates a CreateGoogleIDPUnprocessableEntity with default headers values
func NewCreateGoogleIDPUnprocessableEntity() *CreateGoogleIDPUnprocessableEntity {
	return &CreateGoogleIDPUnprocessableEntity{}
}

/*
CreateGoogleIDPUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type CreateGoogleIDPUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this create google Id p unprocessable entity response has a 2xx status code
func (o *CreateGoogleIDPUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create google Id p unprocessable entity response has a 3xx status code
func (o *CreateGoogleIDPUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create google Id p unprocessable entity response has a 4xx status code
func (o *CreateGoogleIDPUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this create google Id p unprocessable entity response has a 5xx status code
func (o *CreateGoogleIDPUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this create google Id p unprocessable entity response a status code equal to that given
func (o *CreateGoogleIDPUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the create google Id p unprocessable entity response
func (o *CreateGoogleIDPUnprocessableEntity) Code() int {
	return 422
}

func (o *CreateGoogleIDPUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/google][%d] createGoogleIdPUnprocessableEntity %s", 422, payload)
}

func (o *CreateGoogleIDPUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/google][%d] createGoogleIdPUnprocessableEntity %s", 422, payload)
}

func (o *CreateGoogleIDPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateGoogleIDPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateGoogleIDPTooManyRequests creates a CreateGoogleIDPTooManyRequests with default headers values
func NewCreateGoogleIDPTooManyRequests() *CreateGoogleIDPTooManyRequests {
	return &CreateGoogleIDPTooManyRequests{}
}

/*
CreateGoogleIDPTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type CreateGoogleIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this create google Id p too many requests response has a 2xx status code
func (o *CreateGoogleIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create google Id p too many requests response has a 3xx status code
func (o *CreateGoogleIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create google Id p too many requests response has a 4xx status code
func (o *CreateGoogleIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create google Id p too many requests response has a 5xx status code
func (o *CreateGoogleIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create google Id p too many requests response a status code equal to that given
func (o *CreateGoogleIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create google Id p too many requests response
func (o *CreateGoogleIDPTooManyRequests) Code() int {
	return 429
}

func (o *CreateGoogleIDPTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/google][%d] createGoogleIdPTooManyRequests %s", 429, payload)
}

func (o *CreateGoogleIDPTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/google][%d] createGoogleIdPTooManyRequests %s", 429, payload)
}

func (o *CreateGoogleIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateGoogleIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
