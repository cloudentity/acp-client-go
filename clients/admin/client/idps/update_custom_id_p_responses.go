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

// UpdateCustomIDPReader is a Reader for the UpdateCustomIDP structure.
type UpdateCustomIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateCustomIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateCustomIDPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateCustomIDPBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewUpdateCustomIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdateCustomIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateCustomIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewUpdateCustomIDPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdateCustomIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PUT /servers/{wid}/idps/custom/{iid}] updateCustomIDP", response, response.Code())
	}
}

// NewUpdateCustomIDPOK creates a UpdateCustomIDPOK with default headers values
func NewUpdateCustomIDPOK() *UpdateCustomIDPOK {
	return &UpdateCustomIDPOK{}
}

/*
UpdateCustomIDPOK describes a response with status code 200, with default header values.

CustomIDP
*/
type UpdateCustomIDPOK struct {
	Payload *models.CustomIDP
}

// IsSuccess returns true when this update custom Id p o k response has a 2xx status code
func (o *UpdateCustomIDPOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update custom Id p o k response has a 3xx status code
func (o *UpdateCustomIDPOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update custom Id p o k response has a 4xx status code
func (o *UpdateCustomIDPOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update custom Id p o k response has a 5xx status code
func (o *UpdateCustomIDPOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update custom Id p o k response a status code equal to that given
func (o *UpdateCustomIDPOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update custom Id p o k response
func (o *UpdateCustomIDPOK) Code() int {
	return 200
}

func (o *UpdateCustomIDPOK) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/custom/{iid}][%d] updateCustomIdPOK  %+v", 200, o.Payload)
}

func (o *UpdateCustomIDPOK) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/custom/{iid}][%d] updateCustomIdPOK  %+v", 200, o.Payload)
}

func (o *UpdateCustomIDPOK) GetPayload() *models.CustomIDP {
	return o.Payload
}

func (o *UpdateCustomIDPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.CustomIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateCustomIDPBadRequest creates a UpdateCustomIDPBadRequest with default headers values
func NewUpdateCustomIDPBadRequest() *UpdateCustomIDPBadRequest {
	return &UpdateCustomIDPBadRequest{}
}

/*
UpdateCustomIDPBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type UpdateCustomIDPBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this update custom Id p bad request response has a 2xx status code
func (o *UpdateCustomIDPBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update custom Id p bad request response has a 3xx status code
func (o *UpdateCustomIDPBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update custom Id p bad request response has a 4xx status code
func (o *UpdateCustomIDPBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this update custom Id p bad request response has a 5xx status code
func (o *UpdateCustomIDPBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this update custom Id p bad request response a status code equal to that given
func (o *UpdateCustomIDPBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the update custom Id p bad request response
func (o *UpdateCustomIDPBadRequest) Code() int {
	return 400
}

func (o *UpdateCustomIDPBadRequest) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/custom/{iid}][%d] updateCustomIdPBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateCustomIDPBadRequest) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/custom/{iid}][%d] updateCustomIdPBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateCustomIDPBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateCustomIDPBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateCustomIDPUnauthorized creates a UpdateCustomIDPUnauthorized with default headers values
func NewUpdateCustomIDPUnauthorized() *UpdateCustomIDPUnauthorized {
	return &UpdateCustomIDPUnauthorized{}
}

/*
UpdateCustomIDPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type UpdateCustomIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this update custom Id p unauthorized response has a 2xx status code
func (o *UpdateCustomIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update custom Id p unauthorized response has a 3xx status code
func (o *UpdateCustomIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update custom Id p unauthorized response has a 4xx status code
func (o *UpdateCustomIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this update custom Id p unauthorized response has a 5xx status code
func (o *UpdateCustomIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this update custom Id p unauthorized response a status code equal to that given
func (o *UpdateCustomIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the update custom Id p unauthorized response
func (o *UpdateCustomIDPUnauthorized) Code() int {
	return 401
}

func (o *UpdateCustomIDPUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/custom/{iid}][%d] updateCustomIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *UpdateCustomIDPUnauthorized) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/custom/{iid}][%d] updateCustomIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *UpdateCustomIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateCustomIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateCustomIDPForbidden creates a UpdateCustomIDPForbidden with default headers values
func NewUpdateCustomIDPForbidden() *UpdateCustomIDPForbidden {
	return &UpdateCustomIDPForbidden{}
}

/*
UpdateCustomIDPForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdateCustomIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this update custom Id p forbidden response has a 2xx status code
func (o *UpdateCustomIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update custom Id p forbidden response has a 3xx status code
func (o *UpdateCustomIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update custom Id p forbidden response has a 4xx status code
func (o *UpdateCustomIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update custom Id p forbidden response has a 5xx status code
func (o *UpdateCustomIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update custom Id p forbidden response a status code equal to that given
func (o *UpdateCustomIDPForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the update custom Id p forbidden response
func (o *UpdateCustomIDPForbidden) Code() int {
	return 403
}

func (o *UpdateCustomIDPForbidden) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/custom/{iid}][%d] updateCustomIdPForbidden  %+v", 403, o.Payload)
}

func (o *UpdateCustomIDPForbidden) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/custom/{iid}][%d] updateCustomIdPForbidden  %+v", 403, o.Payload)
}

func (o *UpdateCustomIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateCustomIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateCustomIDPNotFound creates a UpdateCustomIDPNotFound with default headers values
func NewUpdateCustomIDPNotFound() *UpdateCustomIDPNotFound {
	return &UpdateCustomIDPNotFound{}
}

/*
UpdateCustomIDPNotFound describes a response with status code 404, with default header values.

Not found
*/
type UpdateCustomIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this update custom Id p not found response has a 2xx status code
func (o *UpdateCustomIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update custom Id p not found response has a 3xx status code
func (o *UpdateCustomIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update custom Id p not found response has a 4xx status code
func (o *UpdateCustomIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this update custom Id p not found response has a 5xx status code
func (o *UpdateCustomIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this update custom Id p not found response a status code equal to that given
func (o *UpdateCustomIDPNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the update custom Id p not found response
func (o *UpdateCustomIDPNotFound) Code() int {
	return 404
}

func (o *UpdateCustomIDPNotFound) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/custom/{iid}][%d] updateCustomIdPNotFound  %+v", 404, o.Payload)
}

func (o *UpdateCustomIDPNotFound) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/custom/{iid}][%d] updateCustomIdPNotFound  %+v", 404, o.Payload)
}

func (o *UpdateCustomIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateCustomIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateCustomIDPUnprocessableEntity creates a UpdateCustomIDPUnprocessableEntity with default headers values
func NewUpdateCustomIDPUnprocessableEntity() *UpdateCustomIDPUnprocessableEntity {
	return &UpdateCustomIDPUnprocessableEntity{}
}

/*
UpdateCustomIDPUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type UpdateCustomIDPUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this update custom Id p unprocessable entity response has a 2xx status code
func (o *UpdateCustomIDPUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update custom Id p unprocessable entity response has a 3xx status code
func (o *UpdateCustomIDPUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update custom Id p unprocessable entity response has a 4xx status code
func (o *UpdateCustomIDPUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this update custom Id p unprocessable entity response has a 5xx status code
func (o *UpdateCustomIDPUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this update custom Id p unprocessable entity response a status code equal to that given
func (o *UpdateCustomIDPUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the update custom Id p unprocessable entity response
func (o *UpdateCustomIDPUnprocessableEntity) Code() int {
	return 422
}

func (o *UpdateCustomIDPUnprocessableEntity) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/custom/{iid}][%d] updateCustomIdPUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *UpdateCustomIDPUnprocessableEntity) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/custom/{iid}][%d] updateCustomIdPUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *UpdateCustomIDPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateCustomIDPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateCustomIDPTooManyRequests creates a UpdateCustomIDPTooManyRequests with default headers values
func NewUpdateCustomIDPTooManyRequests() *UpdateCustomIDPTooManyRequests {
	return &UpdateCustomIDPTooManyRequests{}
}

/*
UpdateCustomIDPTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type UpdateCustomIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this update custom Id p too many requests response has a 2xx status code
func (o *UpdateCustomIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update custom Id p too many requests response has a 3xx status code
func (o *UpdateCustomIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update custom Id p too many requests response has a 4xx status code
func (o *UpdateCustomIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update custom Id p too many requests response has a 5xx status code
func (o *UpdateCustomIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update custom Id p too many requests response a status code equal to that given
func (o *UpdateCustomIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the update custom Id p too many requests response
func (o *UpdateCustomIDPTooManyRequests) Code() int {
	return 429
}

func (o *UpdateCustomIDPTooManyRequests) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/custom/{iid}][%d] updateCustomIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateCustomIDPTooManyRequests) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/custom/{iid}][%d] updateCustomIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateCustomIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateCustomIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
