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

// UpdateAppleIDPReader is a Reader for the UpdateAppleIDP structure.
type UpdateAppleIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateAppleIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateAppleIDPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateAppleIDPBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewUpdateAppleIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdateAppleIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateAppleIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewUpdateAppleIDPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdateAppleIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PUT /servers/{wid}/idps/apple/{iid}] updateAppleIDP", response, response.Code())
	}
}

// NewUpdateAppleIDPOK creates a UpdateAppleIDPOK with default headers values
func NewUpdateAppleIDPOK() *UpdateAppleIDPOK {
	return &UpdateAppleIDPOK{}
}

/*
UpdateAppleIDPOK describes a response with status code 200, with default header values.

AppleIDP
*/
type UpdateAppleIDPOK struct {
	Payload *models.AppleIDP
}

// IsSuccess returns true when this update apple Id p o k response has a 2xx status code
func (o *UpdateAppleIDPOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update apple Id p o k response has a 3xx status code
func (o *UpdateAppleIDPOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update apple Id p o k response has a 4xx status code
func (o *UpdateAppleIDPOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update apple Id p o k response has a 5xx status code
func (o *UpdateAppleIDPOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update apple Id p o k response a status code equal to that given
func (o *UpdateAppleIDPOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update apple Id p o k response
func (o *UpdateAppleIDPOK) Code() int {
	return 200
}

func (o *UpdateAppleIDPOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/apple/{iid}][%d] updateAppleIdPOK %s", 200, payload)
}

func (o *UpdateAppleIDPOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/apple/{iid}][%d] updateAppleIdPOK %s", 200, payload)
}

func (o *UpdateAppleIDPOK) GetPayload() *models.AppleIDP {
	return o.Payload
}

func (o *UpdateAppleIDPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.AppleIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAppleIDPBadRequest creates a UpdateAppleIDPBadRequest with default headers values
func NewUpdateAppleIDPBadRequest() *UpdateAppleIDPBadRequest {
	return &UpdateAppleIDPBadRequest{}
}

/*
UpdateAppleIDPBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type UpdateAppleIDPBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this update apple Id p bad request response has a 2xx status code
func (o *UpdateAppleIDPBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update apple Id p bad request response has a 3xx status code
func (o *UpdateAppleIDPBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update apple Id p bad request response has a 4xx status code
func (o *UpdateAppleIDPBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this update apple Id p bad request response has a 5xx status code
func (o *UpdateAppleIDPBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this update apple Id p bad request response a status code equal to that given
func (o *UpdateAppleIDPBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the update apple Id p bad request response
func (o *UpdateAppleIDPBadRequest) Code() int {
	return 400
}

func (o *UpdateAppleIDPBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/apple/{iid}][%d] updateAppleIdPBadRequest %s", 400, payload)
}

func (o *UpdateAppleIDPBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/apple/{iid}][%d] updateAppleIdPBadRequest %s", 400, payload)
}

func (o *UpdateAppleIDPBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateAppleIDPBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAppleIDPUnauthorized creates a UpdateAppleIDPUnauthorized with default headers values
func NewUpdateAppleIDPUnauthorized() *UpdateAppleIDPUnauthorized {
	return &UpdateAppleIDPUnauthorized{}
}

/*
UpdateAppleIDPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type UpdateAppleIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this update apple Id p unauthorized response has a 2xx status code
func (o *UpdateAppleIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update apple Id p unauthorized response has a 3xx status code
func (o *UpdateAppleIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update apple Id p unauthorized response has a 4xx status code
func (o *UpdateAppleIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this update apple Id p unauthorized response has a 5xx status code
func (o *UpdateAppleIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this update apple Id p unauthorized response a status code equal to that given
func (o *UpdateAppleIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the update apple Id p unauthorized response
func (o *UpdateAppleIDPUnauthorized) Code() int {
	return 401
}

func (o *UpdateAppleIDPUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/apple/{iid}][%d] updateAppleIdPUnauthorized %s", 401, payload)
}

func (o *UpdateAppleIDPUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/apple/{iid}][%d] updateAppleIdPUnauthorized %s", 401, payload)
}

func (o *UpdateAppleIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateAppleIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAppleIDPForbidden creates a UpdateAppleIDPForbidden with default headers values
func NewUpdateAppleIDPForbidden() *UpdateAppleIDPForbidden {
	return &UpdateAppleIDPForbidden{}
}

/*
UpdateAppleIDPForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdateAppleIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this update apple Id p forbidden response has a 2xx status code
func (o *UpdateAppleIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update apple Id p forbidden response has a 3xx status code
func (o *UpdateAppleIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update apple Id p forbidden response has a 4xx status code
func (o *UpdateAppleIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update apple Id p forbidden response has a 5xx status code
func (o *UpdateAppleIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update apple Id p forbidden response a status code equal to that given
func (o *UpdateAppleIDPForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the update apple Id p forbidden response
func (o *UpdateAppleIDPForbidden) Code() int {
	return 403
}

func (o *UpdateAppleIDPForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/apple/{iid}][%d] updateAppleIdPForbidden %s", 403, payload)
}

func (o *UpdateAppleIDPForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/apple/{iid}][%d] updateAppleIdPForbidden %s", 403, payload)
}

func (o *UpdateAppleIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateAppleIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAppleIDPNotFound creates a UpdateAppleIDPNotFound with default headers values
func NewUpdateAppleIDPNotFound() *UpdateAppleIDPNotFound {
	return &UpdateAppleIDPNotFound{}
}

/*
UpdateAppleIDPNotFound describes a response with status code 404, with default header values.

Not found
*/
type UpdateAppleIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this update apple Id p not found response has a 2xx status code
func (o *UpdateAppleIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update apple Id p not found response has a 3xx status code
func (o *UpdateAppleIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update apple Id p not found response has a 4xx status code
func (o *UpdateAppleIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this update apple Id p not found response has a 5xx status code
func (o *UpdateAppleIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this update apple Id p not found response a status code equal to that given
func (o *UpdateAppleIDPNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the update apple Id p not found response
func (o *UpdateAppleIDPNotFound) Code() int {
	return 404
}

func (o *UpdateAppleIDPNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/apple/{iid}][%d] updateAppleIdPNotFound %s", 404, payload)
}

func (o *UpdateAppleIDPNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/apple/{iid}][%d] updateAppleIdPNotFound %s", 404, payload)
}

func (o *UpdateAppleIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateAppleIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAppleIDPUnprocessableEntity creates a UpdateAppleIDPUnprocessableEntity with default headers values
func NewUpdateAppleIDPUnprocessableEntity() *UpdateAppleIDPUnprocessableEntity {
	return &UpdateAppleIDPUnprocessableEntity{}
}

/*
UpdateAppleIDPUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type UpdateAppleIDPUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this update apple Id p unprocessable entity response has a 2xx status code
func (o *UpdateAppleIDPUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update apple Id p unprocessable entity response has a 3xx status code
func (o *UpdateAppleIDPUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update apple Id p unprocessable entity response has a 4xx status code
func (o *UpdateAppleIDPUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this update apple Id p unprocessable entity response has a 5xx status code
func (o *UpdateAppleIDPUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this update apple Id p unprocessable entity response a status code equal to that given
func (o *UpdateAppleIDPUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the update apple Id p unprocessable entity response
func (o *UpdateAppleIDPUnprocessableEntity) Code() int {
	return 422
}

func (o *UpdateAppleIDPUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/apple/{iid}][%d] updateAppleIdPUnprocessableEntity %s", 422, payload)
}

func (o *UpdateAppleIDPUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/apple/{iid}][%d] updateAppleIdPUnprocessableEntity %s", 422, payload)
}

func (o *UpdateAppleIDPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateAppleIDPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAppleIDPTooManyRequests creates a UpdateAppleIDPTooManyRequests with default headers values
func NewUpdateAppleIDPTooManyRequests() *UpdateAppleIDPTooManyRequests {
	return &UpdateAppleIDPTooManyRequests{}
}

/*
UpdateAppleIDPTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type UpdateAppleIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this update apple Id p too many requests response has a 2xx status code
func (o *UpdateAppleIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update apple Id p too many requests response has a 3xx status code
func (o *UpdateAppleIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update apple Id p too many requests response has a 4xx status code
func (o *UpdateAppleIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update apple Id p too many requests response has a 5xx status code
func (o *UpdateAppleIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update apple Id p too many requests response a status code equal to that given
func (o *UpdateAppleIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the update apple Id p too many requests response
func (o *UpdateAppleIDPTooManyRequests) Code() int {
	return 429
}

func (o *UpdateAppleIDPTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/apple/{iid}][%d] updateAppleIdPTooManyRequests %s", 429, payload)
}

func (o *UpdateAppleIDPTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/apple/{iid}][%d] updateAppleIdPTooManyRequests %s", 429, payload)
}

func (o *UpdateAppleIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateAppleIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
