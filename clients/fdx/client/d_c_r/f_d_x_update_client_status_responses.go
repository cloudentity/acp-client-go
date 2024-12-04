// Code generated by go-swagger; DO NOT EDIT.

package d_c_r

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/fdx/models"
)

// FDXUpdateClientStatusReader is a Reader for the FDXUpdateClientStatus structure.
type FDXUpdateClientStatusReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *FDXUpdateClientStatusReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewFDXUpdateClientStatusOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewFDXUpdateClientStatusBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewFDXUpdateClientStatusUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewFDXUpdateClientStatusForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewFDXUpdateClientStatusNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewFDXUpdateClientStatusUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewFDXUpdateClientStatusTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PUT /fdx/clients/{cid}] FDXUpdateClientStatus", response, response.Code())
	}
}

// NewFDXUpdateClientStatusOK creates a FDXUpdateClientStatusOK with default headers values
func NewFDXUpdateClientStatusOK() *FDXUpdateClientStatusOK {
	return &FDXUpdateClientStatusOK{}
}

/*
FDXUpdateClientStatusOK describes a response with status code 200, with default header values.

	Client Status Updated
*/
type FDXUpdateClientStatusOK struct {
}

// IsSuccess returns true when this f d x update client status o k response has a 2xx status code
func (o *FDXUpdateClientStatusOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this f d x update client status o k response has a 3xx status code
func (o *FDXUpdateClientStatusOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this f d x update client status o k response has a 4xx status code
func (o *FDXUpdateClientStatusOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this f d x update client status o k response has a 5xx status code
func (o *FDXUpdateClientStatusOK) IsServerError() bool {
	return false
}

// IsCode returns true when this f d x update client status o k response a status code equal to that given
func (o *FDXUpdateClientStatusOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the f d x update client status o k response
func (o *FDXUpdateClientStatusOK) Code() int {
	return 200
}

func (o *FDXUpdateClientStatusOK) Error() string {
	return fmt.Sprintf("[PUT /fdx/clients/{cid}][%d] fDXUpdateClientStatusOK", 200)
}

func (o *FDXUpdateClientStatusOK) String() string {
	return fmt.Sprintf("[PUT /fdx/clients/{cid}][%d] fDXUpdateClientStatusOK", 200)
}

func (o *FDXUpdateClientStatusOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewFDXUpdateClientStatusBadRequest creates a FDXUpdateClientStatusBadRequest with default headers values
func NewFDXUpdateClientStatusBadRequest() *FDXUpdateClientStatusBadRequest {
	return &FDXUpdateClientStatusBadRequest{}
}

/*
FDXUpdateClientStatusBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type FDXUpdateClientStatusBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this f d x update client status bad request response has a 2xx status code
func (o *FDXUpdateClientStatusBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this f d x update client status bad request response has a 3xx status code
func (o *FDXUpdateClientStatusBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this f d x update client status bad request response has a 4xx status code
func (o *FDXUpdateClientStatusBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this f d x update client status bad request response has a 5xx status code
func (o *FDXUpdateClientStatusBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this f d x update client status bad request response a status code equal to that given
func (o *FDXUpdateClientStatusBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the f d x update client status bad request response
func (o *FDXUpdateClientStatusBadRequest) Code() int {
	return 400
}

func (o *FDXUpdateClientStatusBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /fdx/clients/{cid}][%d] fDXUpdateClientStatusBadRequest %s", 400, payload)
}

func (o *FDXUpdateClientStatusBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /fdx/clients/{cid}][%d] fDXUpdateClientStatusBadRequest %s", 400, payload)
}

func (o *FDXUpdateClientStatusBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *FDXUpdateClientStatusBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewFDXUpdateClientStatusUnauthorized creates a FDXUpdateClientStatusUnauthorized with default headers values
func NewFDXUpdateClientStatusUnauthorized() *FDXUpdateClientStatusUnauthorized {
	return &FDXUpdateClientStatusUnauthorized{}
}

/*
FDXUpdateClientStatusUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type FDXUpdateClientStatusUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this f d x update client status unauthorized response has a 2xx status code
func (o *FDXUpdateClientStatusUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this f d x update client status unauthorized response has a 3xx status code
func (o *FDXUpdateClientStatusUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this f d x update client status unauthorized response has a 4xx status code
func (o *FDXUpdateClientStatusUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this f d x update client status unauthorized response has a 5xx status code
func (o *FDXUpdateClientStatusUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this f d x update client status unauthorized response a status code equal to that given
func (o *FDXUpdateClientStatusUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the f d x update client status unauthorized response
func (o *FDXUpdateClientStatusUnauthorized) Code() int {
	return 401
}

func (o *FDXUpdateClientStatusUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /fdx/clients/{cid}][%d] fDXUpdateClientStatusUnauthorized %s", 401, payload)
}

func (o *FDXUpdateClientStatusUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /fdx/clients/{cid}][%d] fDXUpdateClientStatusUnauthorized %s", 401, payload)
}

func (o *FDXUpdateClientStatusUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *FDXUpdateClientStatusUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewFDXUpdateClientStatusForbidden creates a FDXUpdateClientStatusForbidden with default headers values
func NewFDXUpdateClientStatusForbidden() *FDXUpdateClientStatusForbidden {
	return &FDXUpdateClientStatusForbidden{}
}

/*
FDXUpdateClientStatusForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type FDXUpdateClientStatusForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this f d x update client status forbidden response has a 2xx status code
func (o *FDXUpdateClientStatusForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this f d x update client status forbidden response has a 3xx status code
func (o *FDXUpdateClientStatusForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this f d x update client status forbidden response has a 4xx status code
func (o *FDXUpdateClientStatusForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this f d x update client status forbidden response has a 5xx status code
func (o *FDXUpdateClientStatusForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this f d x update client status forbidden response a status code equal to that given
func (o *FDXUpdateClientStatusForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the f d x update client status forbidden response
func (o *FDXUpdateClientStatusForbidden) Code() int {
	return 403
}

func (o *FDXUpdateClientStatusForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /fdx/clients/{cid}][%d] fDXUpdateClientStatusForbidden %s", 403, payload)
}

func (o *FDXUpdateClientStatusForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /fdx/clients/{cid}][%d] fDXUpdateClientStatusForbidden %s", 403, payload)
}

func (o *FDXUpdateClientStatusForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *FDXUpdateClientStatusForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewFDXUpdateClientStatusNotFound creates a FDXUpdateClientStatusNotFound with default headers values
func NewFDXUpdateClientStatusNotFound() *FDXUpdateClientStatusNotFound {
	return &FDXUpdateClientStatusNotFound{}
}

/*
FDXUpdateClientStatusNotFound describes a response with status code 404, with default header values.

Not found
*/
type FDXUpdateClientStatusNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this f d x update client status not found response has a 2xx status code
func (o *FDXUpdateClientStatusNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this f d x update client status not found response has a 3xx status code
func (o *FDXUpdateClientStatusNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this f d x update client status not found response has a 4xx status code
func (o *FDXUpdateClientStatusNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this f d x update client status not found response has a 5xx status code
func (o *FDXUpdateClientStatusNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this f d x update client status not found response a status code equal to that given
func (o *FDXUpdateClientStatusNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the f d x update client status not found response
func (o *FDXUpdateClientStatusNotFound) Code() int {
	return 404
}

func (o *FDXUpdateClientStatusNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /fdx/clients/{cid}][%d] fDXUpdateClientStatusNotFound %s", 404, payload)
}

func (o *FDXUpdateClientStatusNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /fdx/clients/{cid}][%d] fDXUpdateClientStatusNotFound %s", 404, payload)
}

func (o *FDXUpdateClientStatusNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *FDXUpdateClientStatusNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewFDXUpdateClientStatusUnprocessableEntity creates a FDXUpdateClientStatusUnprocessableEntity with default headers values
func NewFDXUpdateClientStatusUnprocessableEntity() *FDXUpdateClientStatusUnprocessableEntity {
	return &FDXUpdateClientStatusUnprocessableEntity{}
}

/*
FDXUpdateClientStatusUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type FDXUpdateClientStatusUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this f d x update client status unprocessable entity response has a 2xx status code
func (o *FDXUpdateClientStatusUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this f d x update client status unprocessable entity response has a 3xx status code
func (o *FDXUpdateClientStatusUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this f d x update client status unprocessable entity response has a 4xx status code
func (o *FDXUpdateClientStatusUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this f d x update client status unprocessable entity response has a 5xx status code
func (o *FDXUpdateClientStatusUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this f d x update client status unprocessable entity response a status code equal to that given
func (o *FDXUpdateClientStatusUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the f d x update client status unprocessable entity response
func (o *FDXUpdateClientStatusUnprocessableEntity) Code() int {
	return 422
}

func (o *FDXUpdateClientStatusUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /fdx/clients/{cid}][%d] fDXUpdateClientStatusUnprocessableEntity %s", 422, payload)
}

func (o *FDXUpdateClientStatusUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /fdx/clients/{cid}][%d] fDXUpdateClientStatusUnprocessableEntity %s", 422, payload)
}

func (o *FDXUpdateClientStatusUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *FDXUpdateClientStatusUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewFDXUpdateClientStatusTooManyRequests creates a FDXUpdateClientStatusTooManyRequests with default headers values
func NewFDXUpdateClientStatusTooManyRequests() *FDXUpdateClientStatusTooManyRequests {
	return &FDXUpdateClientStatusTooManyRequests{}
}

/*
FDXUpdateClientStatusTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type FDXUpdateClientStatusTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this f d x update client status too many requests response has a 2xx status code
func (o *FDXUpdateClientStatusTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this f d x update client status too many requests response has a 3xx status code
func (o *FDXUpdateClientStatusTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this f d x update client status too many requests response has a 4xx status code
func (o *FDXUpdateClientStatusTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this f d x update client status too many requests response has a 5xx status code
func (o *FDXUpdateClientStatusTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this f d x update client status too many requests response a status code equal to that given
func (o *FDXUpdateClientStatusTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the f d x update client status too many requests response
func (o *FDXUpdateClientStatusTooManyRequests) Code() int {
	return 429
}

func (o *FDXUpdateClientStatusTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /fdx/clients/{cid}][%d] fDXUpdateClientStatusTooManyRequests %s", 429, payload)
}

func (o *FDXUpdateClientStatusTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /fdx/clients/{cid}][%d] fDXUpdateClientStatusTooManyRequests %s", 429, payload)
}

func (o *FDXUpdateClientStatusTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *FDXUpdateClientStatusTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
