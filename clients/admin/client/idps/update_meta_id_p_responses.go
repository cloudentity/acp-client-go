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

// UpdateMetaIDPReader is a Reader for the UpdateMetaIDP structure.
type UpdateMetaIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateMetaIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateMetaIDPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateMetaIDPBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewUpdateMetaIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdateMetaIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateMetaIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewUpdateMetaIDPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdateMetaIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PUT /servers/{wid}/idps/meta/{iid}] updateMetaIDP", response, response.Code())
	}
}

// NewUpdateMetaIDPOK creates a UpdateMetaIDPOK with default headers values
func NewUpdateMetaIDPOK() *UpdateMetaIDPOK {
	return &UpdateMetaIDPOK{}
}

/*
UpdateMetaIDPOK describes a response with status code 200, with default header values.

MetaIDP
*/
type UpdateMetaIDPOK struct {
	Payload *models.MetaIDP
}

// IsSuccess returns true when this update meta Id p o k response has a 2xx status code
func (o *UpdateMetaIDPOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update meta Id p o k response has a 3xx status code
func (o *UpdateMetaIDPOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update meta Id p o k response has a 4xx status code
func (o *UpdateMetaIDPOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update meta Id p o k response has a 5xx status code
func (o *UpdateMetaIDPOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update meta Id p o k response a status code equal to that given
func (o *UpdateMetaIDPOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update meta Id p o k response
func (o *UpdateMetaIDPOK) Code() int {
	return 200
}

func (o *UpdateMetaIDPOK) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/meta/{iid}][%d] updateMetaIdPOK  %+v", 200, o.Payload)
}

func (o *UpdateMetaIDPOK) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/meta/{iid}][%d] updateMetaIdPOK  %+v", 200, o.Payload)
}

func (o *UpdateMetaIDPOK) GetPayload() *models.MetaIDP {
	return o.Payload
}

func (o *UpdateMetaIDPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.MetaIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateMetaIDPBadRequest creates a UpdateMetaIDPBadRequest with default headers values
func NewUpdateMetaIDPBadRequest() *UpdateMetaIDPBadRequest {
	return &UpdateMetaIDPBadRequest{}
}

/*
UpdateMetaIDPBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type UpdateMetaIDPBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this update meta Id p bad request response has a 2xx status code
func (o *UpdateMetaIDPBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update meta Id p bad request response has a 3xx status code
func (o *UpdateMetaIDPBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update meta Id p bad request response has a 4xx status code
func (o *UpdateMetaIDPBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this update meta Id p bad request response has a 5xx status code
func (o *UpdateMetaIDPBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this update meta Id p bad request response a status code equal to that given
func (o *UpdateMetaIDPBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the update meta Id p bad request response
func (o *UpdateMetaIDPBadRequest) Code() int {
	return 400
}

func (o *UpdateMetaIDPBadRequest) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/meta/{iid}][%d] updateMetaIdPBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateMetaIDPBadRequest) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/meta/{iid}][%d] updateMetaIdPBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateMetaIDPBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateMetaIDPBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateMetaIDPUnauthorized creates a UpdateMetaIDPUnauthorized with default headers values
func NewUpdateMetaIDPUnauthorized() *UpdateMetaIDPUnauthorized {
	return &UpdateMetaIDPUnauthorized{}
}

/*
UpdateMetaIDPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type UpdateMetaIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this update meta Id p unauthorized response has a 2xx status code
func (o *UpdateMetaIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update meta Id p unauthorized response has a 3xx status code
func (o *UpdateMetaIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update meta Id p unauthorized response has a 4xx status code
func (o *UpdateMetaIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this update meta Id p unauthorized response has a 5xx status code
func (o *UpdateMetaIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this update meta Id p unauthorized response a status code equal to that given
func (o *UpdateMetaIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the update meta Id p unauthorized response
func (o *UpdateMetaIDPUnauthorized) Code() int {
	return 401
}

func (o *UpdateMetaIDPUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/meta/{iid}][%d] updateMetaIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *UpdateMetaIDPUnauthorized) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/meta/{iid}][%d] updateMetaIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *UpdateMetaIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateMetaIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateMetaIDPForbidden creates a UpdateMetaIDPForbidden with default headers values
func NewUpdateMetaIDPForbidden() *UpdateMetaIDPForbidden {
	return &UpdateMetaIDPForbidden{}
}

/*
UpdateMetaIDPForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdateMetaIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this update meta Id p forbidden response has a 2xx status code
func (o *UpdateMetaIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update meta Id p forbidden response has a 3xx status code
func (o *UpdateMetaIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update meta Id p forbidden response has a 4xx status code
func (o *UpdateMetaIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update meta Id p forbidden response has a 5xx status code
func (o *UpdateMetaIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update meta Id p forbidden response a status code equal to that given
func (o *UpdateMetaIDPForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the update meta Id p forbidden response
func (o *UpdateMetaIDPForbidden) Code() int {
	return 403
}

func (o *UpdateMetaIDPForbidden) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/meta/{iid}][%d] updateMetaIdPForbidden  %+v", 403, o.Payload)
}

func (o *UpdateMetaIDPForbidden) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/meta/{iid}][%d] updateMetaIdPForbidden  %+v", 403, o.Payload)
}

func (o *UpdateMetaIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateMetaIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateMetaIDPNotFound creates a UpdateMetaIDPNotFound with default headers values
func NewUpdateMetaIDPNotFound() *UpdateMetaIDPNotFound {
	return &UpdateMetaIDPNotFound{}
}

/*
UpdateMetaIDPNotFound describes a response with status code 404, with default header values.

Not found
*/
type UpdateMetaIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this update meta Id p not found response has a 2xx status code
func (o *UpdateMetaIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update meta Id p not found response has a 3xx status code
func (o *UpdateMetaIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update meta Id p not found response has a 4xx status code
func (o *UpdateMetaIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this update meta Id p not found response has a 5xx status code
func (o *UpdateMetaIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this update meta Id p not found response a status code equal to that given
func (o *UpdateMetaIDPNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the update meta Id p not found response
func (o *UpdateMetaIDPNotFound) Code() int {
	return 404
}

func (o *UpdateMetaIDPNotFound) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/meta/{iid}][%d] updateMetaIdPNotFound  %+v", 404, o.Payload)
}

func (o *UpdateMetaIDPNotFound) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/meta/{iid}][%d] updateMetaIdPNotFound  %+v", 404, o.Payload)
}

func (o *UpdateMetaIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateMetaIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateMetaIDPUnprocessableEntity creates a UpdateMetaIDPUnprocessableEntity with default headers values
func NewUpdateMetaIDPUnprocessableEntity() *UpdateMetaIDPUnprocessableEntity {
	return &UpdateMetaIDPUnprocessableEntity{}
}

/*
UpdateMetaIDPUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type UpdateMetaIDPUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this update meta Id p unprocessable entity response has a 2xx status code
func (o *UpdateMetaIDPUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update meta Id p unprocessable entity response has a 3xx status code
func (o *UpdateMetaIDPUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update meta Id p unprocessable entity response has a 4xx status code
func (o *UpdateMetaIDPUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this update meta Id p unprocessable entity response has a 5xx status code
func (o *UpdateMetaIDPUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this update meta Id p unprocessable entity response a status code equal to that given
func (o *UpdateMetaIDPUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the update meta Id p unprocessable entity response
func (o *UpdateMetaIDPUnprocessableEntity) Code() int {
	return 422
}

func (o *UpdateMetaIDPUnprocessableEntity) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/meta/{iid}][%d] updateMetaIdPUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *UpdateMetaIDPUnprocessableEntity) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/meta/{iid}][%d] updateMetaIdPUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *UpdateMetaIDPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateMetaIDPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateMetaIDPTooManyRequests creates a UpdateMetaIDPTooManyRequests with default headers values
func NewUpdateMetaIDPTooManyRequests() *UpdateMetaIDPTooManyRequests {
	return &UpdateMetaIDPTooManyRequests{}
}

/*
UpdateMetaIDPTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type UpdateMetaIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this update meta Id p too many requests response has a 2xx status code
func (o *UpdateMetaIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update meta Id p too many requests response has a 3xx status code
func (o *UpdateMetaIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update meta Id p too many requests response has a 4xx status code
func (o *UpdateMetaIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update meta Id p too many requests response has a 5xx status code
func (o *UpdateMetaIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update meta Id p too many requests response a status code equal to that given
func (o *UpdateMetaIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the update meta Id p too many requests response
func (o *UpdateMetaIDPTooManyRequests) Code() int {
	return 429
}

func (o *UpdateMetaIDPTooManyRequests) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/meta/{iid}][%d] updateMetaIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateMetaIDPTooManyRequests) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/meta/{iid}][%d] updateMetaIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateMetaIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateMetaIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
