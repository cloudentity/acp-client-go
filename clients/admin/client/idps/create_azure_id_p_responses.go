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

// CreateAzureIDPReader is a Reader for the CreateAzureIDP structure.
type CreateAzureIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateAzureIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateAzureIDPCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateAzureIDPBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateAzureIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateAzureIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateAzureIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateAzureIDPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateAzureIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /servers/{wid}/idps/azure] createAzureIDP", response, response.Code())
	}
}

// NewCreateAzureIDPCreated creates a CreateAzureIDPCreated with default headers values
func NewCreateAzureIDPCreated() *CreateAzureIDPCreated {
	return &CreateAzureIDPCreated{}
}

/*
CreateAzureIDPCreated describes a response with status code 201, with default header values.

AzureIDP
*/
type CreateAzureIDPCreated struct {
	Payload *models.AzureIDP
}

// IsSuccess returns true when this create azure Id p created response has a 2xx status code
func (o *CreateAzureIDPCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create azure Id p created response has a 3xx status code
func (o *CreateAzureIDPCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create azure Id p created response has a 4xx status code
func (o *CreateAzureIDPCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create azure Id p created response has a 5xx status code
func (o *CreateAzureIDPCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create azure Id p created response a status code equal to that given
func (o *CreateAzureIDPCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create azure Id p created response
func (o *CreateAzureIDPCreated) Code() int {
	return 201
}

func (o *CreateAzureIDPCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/azure][%d] createAzureIdPCreated %s", 201, payload)
}

func (o *CreateAzureIDPCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/azure][%d] createAzureIdPCreated %s", 201, payload)
}

func (o *CreateAzureIDPCreated) GetPayload() *models.AzureIDP {
	return o.Payload
}

func (o *CreateAzureIDPCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.AzureIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAzureIDPBadRequest creates a CreateAzureIDPBadRequest with default headers values
func NewCreateAzureIDPBadRequest() *CreateAzureIDPBadRequest {
	return &CreateAzureIDPBadRequest{}
}

/*
CreateAzureIDPBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type CreateAzureIDPBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this create azure Id p bad request response has a 2xx status code
func (o *CreateAzureIDPBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create azure Id p bad request response has a 3xx status code
func (o *CreateAzureIDPBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create azure Id p bad request response has a 4xx status code
func (o *CreateAzureIDPBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create azure Id p bad request response has a 5xx status code
func (o *CreateAzureIDPBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create azure Id p bad request response a status code equal to that given
func (o *CreateAzureIDPBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create azure Id p bad request response
func (o *CreateAzureIDPBadRequest) Code() int {
	return 400
}

func (o *CreateAzureIDPBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/azure][%d] createAzureIdPBadRequest %s", 400, payload)
}

func (o *CreateAzureIDPBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/azure][%d] createAzureIdPBadRequest %s", 400, payload)
}

func (o *CreateAzureIDPBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAzureIDPBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAzureIDPUnauthorized creates a CreateAzureIDPUnauthorized with default headers values
func NewCreateAzureIDPUnauthorized() *CreateAzureIDPUnauthorized {
	return &CreateAzureIDPUnauthorized{}
}

/*
CreateAzureIDPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CreateAzureIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this create azure Id p unauthorized response has a 2xx status code
func (o *CreateAzureIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create azure Id p unauthorized response has a 3xx status code
func (o *CreateAzureIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create azure Id p unauthorized response has a 4xx status code
func (o *CreateAzureIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create azure Id p unauthorized response has a 5xx status code
func (o *CreateAzureIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create azure Id p unauthorized response a status code equal to that given
func (o *CreateAzureIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the create azure Id p unauthorized response
func (o *CreateAzureIDPUnauthorized) Code() int {
	return 401
}

func (o *CreateAzureIDPUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/azure][%d] createAzureIdPUnauthorized %s", 401, payload)
}

func (o *CreateAzureIDPUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/azure][%d] createAzureIdPUnauthorized %s", 401, payload)
}

func (o *CreateAzureIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAzureIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAzureIDPForbidden creates a CreateAzureIDPForbidden with default headers values
func NewCreateAzureIDPForbidden() *CreateAzureIDPForbidden {
	return &CreateAzureIDPForbidden{}
}

/*
CreateAzureIDPForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateAzureIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this create azure Id p forbidden response has a 2xx status code
func (o *CreateAzureIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create azure Id p forbidden response has a 3xx status code
func (o *CreateAzureIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create azure Id p forbidden response has a 4xx status code
func (o *CreateAzureIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create azure Id p forbidden response has a 5xx status code
func (o *CreateAzureIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create azure Id p forbidden response a status code equal to that given
func (o *CreateAzureIDPForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create azure Id p forbidden response
func (o *CreateAzureIDPForbidden) Code() int {
	return 403
}

func (o *CreateAzureIDPForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/azure][%d] createAzureIdPForbidden %s", 403, payload)
}

func (o *CreateAzureIDPForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/azure][%d] createAzureIdPForbidden %s", 403, payload)
}

func (o *CreateAzureIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAzureIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAzureIDPNotFound creates a CreateAzureIDPNotFound with default headers values
func NewCreateAzureIDPNotFound() *CreateAzureIDPNotFound {
	return &CreateAzureIDPNotFound{}
}

/*
CreateAzureIDPNotFound describes a response with status code 404, with default header values.

Not found
*/
type CreateAzureIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this create azure Id p not found response has a 2xx status code
func (o *CreateAzureIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create azure Id p not found response has a 3xx status code
func (o *CreateAzureIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create azure Id p not found response has a 4xx status code
func (o *CreateAzureIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this create azure Id p not found response has a 5xx status code
func (o *CreateAzureIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this create azure Id p not found response a status code equal to that given
func (o *CreateAzureIDPNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the create azure Id p not found response
func (o *CreateAzureIDPNotFound) Code() int {
	return 404
}

func (o *CreateAzureIDPNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/azure][%d] createAzureIdPNotFound %s", 404, payload)
}

func (o *CreateAzureIDPNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/azure][%d] createAzureIdPNotFound %s", 404, payload)
}

func (o *CreateAzureIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAzureIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAzureIDPUnprocessableEntity creates a CreateAzureIDPUnprocessableEntity with default headers values
func NewCreateAzureIDPUnprocessableEntity() *CreateAzureIDPUnprocessableEntity {
	return &CreateAzureIDPUnprocessableEntity{}
}

/*
CreateAzureIDPUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type CreateAzureIDPUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this create azure Id p unprocessable entity response has a 2xx status code
func (o *CreateAzureIDPUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create azure Id p unprocessable entity response has a 3xx status code
func (o *CreateAzureIDPUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create azure Id p unprocessable entity response has a 4xx status code
func (o *CreateAzureIDPUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this create azure Id p unprocessable entity response has a 5xx status code
func (o *CreateAzureIDPUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this create azure Id p unprocessable entity response a status code equal to that given
func (o *CreateAzureIDPUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the create azure Id p unprocessable entity response
func (o *CreateAzureIDPUnprocessableEntity) Code() int {
	return 422
}

func (o *CreateAzureIDPUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/azure][%d] createAzureIdPUnprocessableEntity %s", 422, payload)
}

func (o *CreateAzureIDPUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/azure][%d] createAzureIdPUnprocessableEntity %s", 422, payload)
}

func (o *CreateAzureIDPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAzureIDPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAzureIDPTooManyRequests creates a CreateAzureIDPTooManyRequests with default headers values
func NewCreateAzureIDPTooManyRequests() *CreateAzureIDPTooManyRequests {
	return &CreateAzureIDPTooManyRequests{}
}

/*
CreateAzureIDPTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type CreateAzureIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this create azure Id p too many requests response has a 2xx status code
func (o *CreateAzureIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create azure Id p too many requests response has a 3xx status code
func (o *CreateAzureIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create azure Id p too many requests response has a 4xx status code
func (o *CreateAzureIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create azure Id p too many requests response has a 5xx status code
func (o *CreateAzureIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create azure Id p too many requests response a status code equal to that given
func (o *CreateAzureIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create azure Id p too many requests response
func (o *CreateAzureIDPTooManyRequests) Code() int {
	return 429
}

func (o *CreateAzureIDPTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/azure][%d] createAzureIdPTooManyRequests %s", 429, payload)
}

func (o *CreateAzureIDPTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/azure][%d] createAzureIdPTooManyRequests %s", 429, payload)
}

func (o *CreateAzureIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAzureIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
