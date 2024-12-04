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

// CreateIntelliTrustIDPReader is a Reader for the CreateIntelliTrustIDP structure.
type CreateIntelliTrustIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateIntelliTrustIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateIntelliTrustIDPCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateIntelliTrustIDPBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateIntelliTrustIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateIntelliTrustIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateIntelliTrustIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateIntelliTrustIDPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateIntelliTrustIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /servers/{wid}/idps/intelli_trust] createIntelliTrustIDP", response, response.Code())
	}
}

// NewCreateIntelliTrustIDPCreated creates a CreateIntelliTrustIDPCreated with default headers values
func NewCreateIntelliTrustIDPCreated() *CreateIntelliTrustIDPCreated {
	return &CreateIntelliTrustIDPCreated{}
}

/*
CreateIntelliTrustIDPCreated describes a response with status code 201, with default header values.

IntelliTrustIDP
*/
type CreateIntelliTrustIDPCreated struct {
	Payload *models.IntelliTrustIDP
}

// IsSuccess returns true when this create intelli trust Id p created response has a 2xx status code
func (o *CreateIntelliTrustIDPCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create intelli trust Id p created response has a 3xx status code
func (o *CreateIntelliTrustIDPCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create intelli trust Id p created response has a 4xx status code
func (o *CreateIntelliTrustIDPCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create intelli trust Id p created response has a 5xx status code
func (o *CreateIntelliTrustIDPCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create intelli trust Id p created response a status code equal to that given
func (o *CreateIntelliTrustIDPCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create intelli trust Id p created response
func (o *CreateIntelliTrustIDPCreated) Code() int {
	return 201
}

func (o *CreateIntelliTrustIDPCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/intelli_trust][%d] createIntelliTrustIdPCreated %s", 201, payload)
}

func (o *CreateIntelliTrustIDPCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/intelli_trust][%d] createIntelliTrustIdPCreated %s", 201, payload)
}

func (o *CreateIntelliTrustIDPCreated) GetPayload() *models.IntelliTrustIDP {
	return o.Payload
}

func (o *CreateIntelliTrustIDPCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.IntelliTrustIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateIntelliTrustIDPBadRequest creates a CreateIntelliTrustIDPBadRequest with default headers values
func NewCreateIntelliTrustIDPBadRequest() *CreateIntelliTrustIDPBadRequest {
	return &CreateIntelliTrustIDPBadRequest{}
}

/*
CreateIntelliTrustIDPBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type CreateIntelliTrustIDPBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this create intelli trust Id p bad request response has a 2xx status code
func (o *CreateIntelliTrustIDPBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create intelli trust Id p bad request response has a 3xx status code
func (o *CreateIntelliTrustIDPBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create intelli trust Id p bad request response has a 4xx status code
func (o *CreateIntelliTrustIDPBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create intelli trust Id p bad request response has a 5xx status code
func (o *CreateIntelliTrustIDPBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create intelli trust Id p bad request response a status code equal to that given
func (o *CreateIntelliTrustIDPBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create intelli trust Id p bad request response
func (o *CreateIntelliTrustIDPBadRequest) Code() int {
	return 400
}

func (o *CreateIntelliTrustIDPBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/intelli_trust][%d] createIntelliTrustIdPBadRequest %s", 400, payload)
}

func (o *CreateIntelliTrustIDPBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/intelli_trust][%d] createIntelliTrustIdPBadRequest %s", 400, payload)
}

func (o *CreateIntelliTrustIDPBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateIntelliTrustIDPBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateIntelliTrustIDPUnauthorized creates a CreateIntelliTrustIDPUnauthorized with default headers values
func NewCreateIntelliTrustIDPUnauthorized() *CreateIntelliTrustIDPUnauthorized {
	return &CreateIntelliTrustIDPUnauthorized{}
}

/*
CreateIntelliTrustIDPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CreateIntelliTrustIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this create intelli trust Id p unauthorized response has a 2xx status code
func (o *CreateIntelliTrustIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create intelli trust Id p unauthorized response has a 3xx status code
func (o *CreateIntelliTrustIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create intelli trust Id p unauthorized response has a 4xx status code
func (o *CreateIntelliTrustIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create intelli trust Id p unauthorized response has a 5xx status code
func (o *CreateIntelliTrustIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create intelli trust Id p unauthorized response a status code equal to that given
func (o *CreateIntelliTrustIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the create intelli trust Id p unauthorized response
func (o *CreateIntelliTrustIDPUnauthorized) Code() int {
	return 401
}

func (o *CreateIntelliTrustIDPUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/intelli_trust][%d] createIntelliTrustIdPUnauthorized %s", 401, payload)
}

func (o *CreateIntelliTrustIDPUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/intelli_trust][%d] createIntelliTrustIdPUnauthorized %s", 401, payload)
}

func (o *CreateIntelliTrustIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateIntelliTrustIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateIntelliTrustIDPForbidden creates a CreateIntelliTrustIDPForbidden with default headers values
func NewCreateIntelliTrustIDPForbidden() *CreateIntelliTrustIDPForbidden {
	return &CreateIntelliTrustIDPForbidden{}
}

/*
CreateIntelliTrustIDPForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateIntelliTrustIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this create intelli trust Id p forbidden response has a 2xx status code
func (o *CreateIntelliTrustIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create intelli trust Id p forbidden response has a 3xx status code
func (o *CreateIntelliTrustIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create intelli trust Id p forbidden response has a 4xx status code
func (o *CreateIntelliTrustIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create intelli trust Id p forbidden response has a 5xx status code
func (o *CreateIntelliTrustIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create intelli trust Id p forbidden response a status code equal to that given
func (o *CreateIntelliTrustIDPForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create intelli trust Id p forbidden response
func (o *CreateIntelliTrustIDPForbidden) Code() int {
	return 403
}

func (o *CreateIntelliTrustIDPForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/intelli_trust][%d] createIntelliTrustIdPForbidden %s", 403, payload)
}

func (o *CreateIntelliTrustIDPForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/intelli_trust][%d] createIntelliTrustIdPForbidden %s", 403, payload)
}

func (o *CreateIntelliTrustIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateIntelliTrustIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateIntelliTrustIDPNotFound creates a CreateIntelliTrustIDPNotFound with default headers values
func NewCreateIntelliTrustIDPNotFound() *CreateIntelliTrustIDPNotFound {
	return &CreateIntelliTrustIDPNotFound{}
}

/*
CreateIntelliTrustIDPNotFound describes a response with status code 404, with default header values.

Not found
*/
type CreateIntelliTrustIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this create intelli trust Id p not found response has a 2xx status code
func (o *CreateIntelliTrustIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create intelli trust Id p not found response has a 3xx status code
func (o *CreateIntelliTrustIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create intelli trust Id p not found response has a 4xx status code
func (o *CreateIntelliTrustIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this create intelli trust Id p not found response has a 5xx status code
func (o *CreateIntelliTrustIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this create intelli trust Id p not found response a status code equal to that given
func (o *CreateIntelliTrustIDPNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the create intelli trust Id p not found response
func (o *CreateIntelliTrustIDPNotFound) Code() int {
	return 404
}

func (o *CreateIntelliTrustIDPNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/intelli_trust][%d] createIntelliTrustIdPNotFound %s", 404, payload)
}

func (o *CreateIntelliTrustIDPNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/intelli_trust][%d] createIntelliTrustIdPNotFound %s", 404, payload)
}

func (o *CreateIntelliTrustIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateIntelliTrustIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateIntelliTrustIDPUnprocessableEntity creates a CreateIntelliTrustIDPUnprocessableEntity with default headers values
func NewCreateIntelliTrustIDPUnprocessableEntity() *CreateIntelliTrustIDPUnprocessableEntity {
	return &CreateIntelliTrustIDPUnprocessableEntity{}
}

/*
CreateIntelliTrustIDPUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type CreateIntelliTrustIDPUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this create intelli trust Id p unprocessable entity response has a 2xx status code
func (o *CreateIntelliTrustIDPUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create intelli trust Id p unprocessable entity response has a 3xx status code
func (o *CreateIntelliTrustIDPUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create intelli trust Id p unprocessable entity response has a 4xx status code
func (o *CreateIntelliTrustIDPUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this create intelli trust Id p unprocessable entity response has a 5xx status code
func (o *CreateIntelliTrustIDPUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this create intelli trust Id p unprocessable entity response a status code equal to that given
func (o *CreateIntelliTrustIDPUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the create intelli trust Id p unprocessable entity response
func (o *CreateIntelliTrustIDPUnprocessableEntity) Code() int {
	return 422
}

func (o *CreateIntelliTrustIDPUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/intelli_trust][%d] createIntelliTrustIdPUnprocessableEntity %s", 422, payload)
}

func (o *CreateIntelliTrustIDPUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/intelli_trust][%d] createIntelliTrustIdPUnprocessableEntity %s", 422, payload)
}

func (o *CreateIntelliTrustIDPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateIntelliTrustIDPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateIntelliTrustIDPTooManyRequests creates a CreateIntelliTrustIDPTooManyRequests with default headers values
func NewCreateIntelliTrustIDPTooManyRequests() *CreateIntelliTrustIDPTooManyRequests {
	return &CreateIntelliTrustIDPTooManyRequests{}
}

/*
CreateIntelliTrustIDPTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type CreateIntelliTrustIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this create intelli trust Id p too many requests response has a 2xx status code
func (o *CreateIntelliTrustIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create intelli trust Id p too many requests response has a 3xx status code
func (o *CreateIntelliTrustIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create intelli trust Id p too many requests response has a 4xx status code
func (o *CreateIntelliTrustIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create intelli trust Id p too many requests response has a 5xx status code
func (o *CreateIntelliTrustIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create intelli trust Id p too many requests response a status code equal to that given
func (o *CreateIntelliTrustIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create intelli trust Id p too many requests response
func (o *CreateIntelliTrustIDPTooManyRequests) Code() int {
	return 429
}

func (o *CreateIntelliTrustIDPTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/intelli_trust][%d] createIntelliTrustIdPTooManyRequests %s", 429, payload)
}

func (o *CreateIntelliTrustIDPTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/idps/intelli_trust][%d] createIntelliTrustIdPTooManyRequests %s", 429, payload)
}

func (o *CreateIntelliTrustIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateIntelliTrustIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
