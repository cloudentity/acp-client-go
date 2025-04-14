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

// CreateExternalIDPReader is a Reader for the CreateExternalIDP structure.
type CreateExternalIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateExternalIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateExternalIDPCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateExternalIDPBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateExternalIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateExternalIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateExternalIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateExternalIDPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateExternalIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /servers/{wid}/idps/external] createExternalIDP", response, response.Code())
	}
}

// NewCreateExternalIDPCreated creates a CreateExternalIDPCreated with default headers values
func NewCreateExternalIDPCreated() *CreateExternalIDPCreated {
	return &CreateExternalIDPCreated{}
}

/*
CreateExternalIDPCreated describes a response with status code 201, with default header values.

ExternalIDP
*/
type CreateExternalIDPCreated struct {
	Payload *models.ExternalIDP
}

// IsSuccess returns true when this create external Id p created response has a 2xx status code
func (o *CreateExternalIDPCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create external Id p created response has a 3xx status code
func (o *CreateExternalIDPCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create external Id p created response has a 4xx status code
func (o *CreateExternalIDPCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create external Id p created response has a 5xx status code
func (o *CreateExternalIDPCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create external Id p created response a status code equal to that given
func (o *CreateExternalIDPCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create external Id p created response
func (o *CreateExternalIDPCreated) Code() int {
	return 201
}

func (o *CreateExternalIDPCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/external][%d] createExternalIdPCreated %s", 201, payload)
}

func (o *CreateExternalIDPCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/external][%d] createExternalIdPCreated %s", 201, payload)
}

func (o *CreateExternalIDPCreated) GetPayload() *models.ExternalIDP {
	return o.Payload
}

func (o *CreateExternalIDPCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ExternalIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateExternalIDPBadRequest creates a CreateExternalIDPBadRequest with default headers values
func NewCreateExternalIDPBadRequest() *CreateExternalIDPBadRequest {
	return &CreateExternalIDPBadRequest{}
}

/*
CreateExternalIDPBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type CreateExternalIDPBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this create external Id p bad request response has a 2xx status code
func (o *CreateExternalIDPBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create external Id p bad request response has a 3xx status code
func (o *CreateExternalIDPBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create external Id p bad request response has a 4xx status code
func (o *CreateExternalIDPBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create external Id p bad request response has a 5xx status code
func (o *CreateExternalIDPBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create external Id p bad request response a status code equal to that given
func (o *CreateExternalIDPBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create external Id p bad request response
func (o *CreateExternalIDPBadRequest) Code() int {
	return 400
}

func (o *CreateExternalIDPBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/external][%d] createExternalIdPBadRequest %s", 400, payload)
}

func (o *CreateExternalIDPBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/external][%d] createExternalIdPBadRequest %s", 400, payload)
}

func (o *CreateExternalIDPBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateExternalIDPBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateExternalIDPUnauthorized creates a CreateExternalIDPUnauthorized with default headers values
func NewCreateExternalIDPUnauthorized() *CreateExternalIDPUnauthorized {
	return &CreateExternalIDPUnauthorized{}
}

/*
CreateExternalIDPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CreateExternalIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this create external Id p unauthorized response has a 2xx status code
func (o *CreateExternalIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create external Id p unauthorized response has a 3xx status code
func (o *CreateExternalIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create external Id p unauthorized response has a 4xx status code
func (o *CreateExternalIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create external Id p unauthorized response has a 5xx status code
func (o *CreateExternalIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create external Id p unauthorized response a status code equal to that given
func (o *CreateExternalIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the create external Id p unauthorized response
func (o *CreateExternalIDPUnauthorized) Code() int {
	return 401
}

func (o *CreateExternalIDPUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/external][%d] createExternalIdPUnauthorized %s", 401, payload)
}

func (o *CreateExternalIDPUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/external][%d] createExternalIdPUnauthorized %s", 401, payload)
}

func (o *CreateExternalIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateExternalIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateExternalIDPForbidden creates a CreateExternalIDPForbidden with default headers values
func NewCreateExternalIDPForbidden() *CreateExternalIDPForbidden {
	return &CreateExternalIDPForbidden{}
}

/*
CreateExternalIDPForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateExternalIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this create external Id p forbidden response has a 2xx status code
func (o *CreateExternalIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create external Id p forbidden response has a 3xx status code
func (o *CreateExternalIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create external Id p forbidden response has a 4xx status code
func (o *CreateExternalIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create external Id p forbidden response has a 5xx status code
func (o *CreateExternalIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create external Id p forbidden response a status code equal to that given
func (o *CreateExternalIDPForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create external Id p forbidden response
func (o *CreateExternalIDPForbidden) Code() int {
	return 403
}

func (o *CreateExternalIDPForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/external][%d] createExternalIdPForbidden %s", 403, payload)
}

func (o *CreateExternalIDPForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/external][%d] createExternalIdPForbidden %s", 403, payload)
}

func (o *CreateExternalIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateExternalIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateExternalIDPNotFound creates a CreateExternalIDPNotFound with default headers values
func NewCreateExternalIDPNotFound() *CreateExternalIDPNotFound {
	return &CreateExternalIDPNotFound{}
}

/*
CreateExternalIDPNotFound describes a response with status code 404, with default header values.

Not found
*/
type CreateExternalIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this create external Id p not found response has a 2xx status code
func (o *CreateExternalIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create external Id p not found response has a 3xx status code
func (o *CreateExternalIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create external Id p not found response has a 4xx status code
func (o *CreateExternalIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this create external Id p not found response has a 5xx status code
func (o *CreateExternalIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this create external Id p not found response a status code equal to that given
func (o *CreateExternalIDPNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the create external Id p not found response
func (o *CreateExternalIDPNotFound) Code() int {
	return 404
}

func (o *CreateExternalIDPNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/external][%d] createExternalIdPNotFound %s", 404, payload)
}

func (o *CreateExternalIDPNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/external][%d] createExternalIdPNotFound %s", 404, payload)
}

func (o *CreateExternalIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateExternalIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateExternalIDPUnprocessableEntity creates a CreateExternalIDPUnprocessableEntity with default headers values
func NewCreateExternalIDPUnprocessableEntity() *CreateExternalIDPUnprocessableEntity {
	return &CreateExternalIDPUnprocessableEntity{}
}

/*
CreateExternalIDPUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type CreateExternalIDPUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this create external Id p unprocessable entity response has a 2xx status code
func (o *CreateExternalIDPUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create external Id p unprocessable entity response has a 3xx status code
func (o *CreateExternalIDPUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create external Id p unprocessable entity response has a 4xx status code
func (o *CreateExternalIDPUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this create external Id p unprocessable entity response has a 5xx status code
func (o *CreateExternalIDPUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this create external Id p unprocessable entity response a status code equal to that given
func (o *CreateExternalIDPUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the create external Id p unprocessable entity response
func (o *CreateExternalIDPUnprocessableEntity) Code() int {
	return 422
}

func (o *CreateExternalIDPUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/external][%d] createExternalIdPUnprocessableEntity %s", 422, payload)
}

func (o *CreateExternalIDPUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/external][%d] createExternalIdPUnprocessableEntity %s", 422, payload)
}

func (o *CreateExternalIDPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateExternalIDPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateExternalIDPTooManyRequests creates a CreateExternalIDPTooManyRequests with default headers values
func NewCreateExternalIDPTooManyRequests() *CreateExternalIDPTooManyRequests {
	return &CreateExternalIDPTooManyRequests{}
}

/*
CreateExternalIDPTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type CreateExternalIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this create external Id p too many requests response has a 2xx status code
func (o *CreateExternalIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create external Id p too many requests response has a 3xx status code
func (o *CreateExternalIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create external Id p too many requests response has a 4xx status code
func (o *CreateExternalIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create external Id p too many requests response has a 5xx status code
func (o *CreateExternalIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create external Id p too many requests response a status code equal to that given
func (o *CreateExternalIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create external Id p too many requests response
func (o *CreateExternalIDPTooManyRequests) Code() int {
	return 429
}

func (o *CreateExternalIDPTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/external][%d] createExternalIdPTooManyRequests %s", 429, payload)
}

func (o *CreateExternalIDPTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/external][%d] createExternalIdPTooManyRequests %s", 429, payload)
}

func (o *CreateExternalIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateExternalIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
