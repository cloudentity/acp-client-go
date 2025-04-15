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

// UpdateXIDPReader is a Reader for the UpdateXIDP structure.
type UpdateXIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateXIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateXIDPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateXIDPBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewUpdateXIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdateXIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateXIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewUpdateXIDPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdateXIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PUT /servers/{wid}/idps/x/{iid}] updateXIDP", response, response.Code())
	}
}

// NewUpdateXIDPOK creates a UpdateXIDPOK with default headers values
func NewUpdateXIDPOK() *UpdateXIDPOK {
	return &UpdateXIDPOK{}
}

/*
UpdateXIDPOK describes a response with status code 200, with default header values.

XIDP
*/
type UpdateXIDPOK struct {
	Payload *models.XIDP
}

// IsSuccess returns true when this update x Id p o k response has a 2xx status code
func (o *UpdateXIDPOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update x Id p o k response has a 3xx status code
func (o *UpdateXIDPOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update x Id p o k response has a 4xx status code
func (o *UpdateXIDPOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update x Id p o k response has a 5xx status code
func (o *UpdateXIDPOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update x Id p o k response a status code equal to that given
func (o *UpdateXIDPOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update x Id p o k response
func (o *UpdateXIDPOK) Code() int {
	return 200
}

func (o *UpdateXIDPOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/x/{iid}][%d] updateXIdPOK %s", 200, payload)
}

func (o *UpdateXIDPOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/x/{iid}][%d] updateXIdPOK %s", 200, payload)
}

func (o *UpdateXIDPOK) GetPayload() *models.XIDP {
	return o.Payload
}

func (o *UpdateXIDPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.XIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateXIDPBadRequest creates a UpdateXIDPBadRequest with default headers values
func NewUpdateXIDPBadRequest() *UpdateXIDPBadRequest {
	return &UpdateXIDPBadRequest{}
}

/*
UpdateXIDPBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type UpdateXIDPBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this update x Id p bad request response has a 2xx status code
func (o *UpdateXIDPBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update x Id p bad request response has a 3xx status code
func (o *UpdateXIDPBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update x Id p bad request response has a 4xx status code
func (o *UpdateXIDPBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this update x Id p bad request response has a 5xx status code
func (o *UpdateXIDPBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this update x Id p bad request response a status code equal to that given
func (o *UpdateXIDPBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the update x Id p bad request response
func (o *UpdateXIDPBadRequest) Code() int {
	return 400
}

func (o *UpdateXIDPBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/x/{iid}][%d] updateXIdPBadRequest %s", 400, payload)
}

func (o *UpdateXIDPBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/x/{iid}][%d] updateXIdPBadRequest %s", 400, payload)
}

func (o *UpdateXIDPBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateXIDPBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateXIDPUnauthorized creates a UpdateXIDPUnauthorized with default headers values
func NewUpdateXIDPUnauthorized() *UpdateXIDPUnauthorized {
	return &UpdateXIDPUnauthorized{}
}

/*
UpdateXIDPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type UpdateXIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this update x Id p unauthorized response has a 2xx status code
func (o *UpdateXIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update x Id p unauthorized response has a 3xx status code
func (o *UpdateXIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update x Id p unauthorized response has a 4xx status code
func (o *UpdateXIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this update x Id p unauthorized response has a 5xx status code
func (o *UpdateXIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this update x Id p unauthorized response a status code equal to that given
func (o *UpdateXIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the update x Id p unauthorized response
func (o *UpdateXIDPUnauthorized) Code() int {
	return 401
}

func (o *UpdateXIDPUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/x/{iid}][%d] updateXIdPUnauthorized %s", 401, payload)
}

func (o *UpdateXIDPUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/x/{iid}][%d] updateXIdPUnauthorized %s", 401, payload)
}

func (o *UpdateXIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateXIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateXIDPForbidden creates a UpdateXIDPForbidden with default headers values
func NewUpdateXIDPForbidden() *UpdateXIDPForbidden {
	return &UpdateXIDPForbidden{}
}

/*
UpdateXIDPForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdateXIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this update x Id p forbidden response has a 2xx status code
func (o *UpdateXIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update x Id p forbidden response has a 3xx status code
func (o *UpdateXIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update x Id p forbidden response has a 4xx status code
func (o *UpdateXIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update x Id p forbidden response has a 5xx status code
func (o *UpdateXIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update x Id p forbidden response a status code equal to that given
func (o *UpdateXIDPForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the update x Id p forbidden response
func (o *UpdateXIDPForbidden) Code() int {
	return 403
}

func (o *UpdateXIDPForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/x/{iid}][%d] updateXIdPForbidden %s", 403, payload)
}

func (o *UpdateXIDPForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/x/{iid}][%d] updateXIdPForbidden %s", 403, payload)
}

func (o *UpdateXIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateXIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateXIDPNotFound creates a UpdateXIDPNotFound with default headers values
func NewUpdateXIDPNotFound() *UpdateXIDPNotFound {
	return &UpdateXIDPNotFound{}
}

/*
UpdateXIDPNotFound describes a response with status code 404, with default header values.

Not found
*/
type UpdateXIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this update x Id p not found response has a 2xx status code
func (o *UpdateXIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update x Id p not found response has a 3xx status code
func (o *UpdateXIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update x Id p not found response has a 4xx status code
func (o *UpdateXIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this update x Id p not found response has a 5xx status code
func (o *UpdateXIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this update x Id p not found response a status code equal to that given
func (o *UpdateXIDPNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the update x Id p not found response
func (o *UpdateXIDPNotFound) Code() int {
	return 404
}

func (o *UpdateXIDPNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/x/{iid}][%d] updateXIdPNotFound %s", 404, payload)
}

func (o *UpdateXIDPNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/x/{iid}][%d] updateXIdPNotFound %s", 404, payload)
}

func (o *UpdateXIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateXIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateXIDPUnprocessableEntity creates a UpdateXIDPUnprocessableEntity with default headers values
func NewUpdateXIDPUnprocessableEntity() *UpdateXIDPUnprocessableEntity {
	return &UpdateXIDPUnprocessableEntity{}
}

/*
UpdateXIDPUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type UpdateXIDPUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this update x Id p unprocessable entity response has a 2xx status code
func (o *UpdateXIDPUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update x Id p unprocessable entity response has a 3xx status code
func (o *UpdateXIDPUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update x Id p unprocessable entity response has a 4xx status code
func (o *UpdateXIDPUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this update x Id p unprocessable entity response has a 5xx status code
func (o *UpdateXIDPUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this update x Id p unprocessable entity response a status code equal to that given
func (o *UpdateXIDPUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the update x Id p unprocessable entity response
func (o *UpdateXIDPUnprocessableEntity) Code() int {
	return 422
}

func (o *UpdateXIDPUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/x/{iid}][%d] updateXIdPUnprocessableEntity %s", 422, payload)
}

func (o *UpdateXIDPUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/x/{iid}][%d] updateXIdPUnprocessableEntity %s", 422, payload)
}

func (o *UpdateXIDPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateXIDPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateXIDPTooManyRequests creates a UpdateXIDPTooManyRequests with default headers values
func NewUpdateXIDPTooManyRequests() *UpdateXIDPTooManyRequests {
	return &UpdateXIDPTooManyRequests{}
}

/*
UpdateXIDPTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type UpdateXIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this update x Id p too many requests response has a 2xx status code
func (o *UpdateXIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update x Id p too many requests response has a 3xx status code
func (o *UpdateXIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update x Id p too many requests response has a 4xx status code
func (o *UpdateXIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update x Id p too many requests response has a 5xx status code
func (o *UpdateXIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update x Id p too many requests response a status code equal to that given
func (o *UpdateXIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the update x Id p too many requests response
func (o *UpdateXIDPTooManyRequests) Code() int {
	return 429
}

func (o *UpdateXIDPTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/x/{iid}][%d] updateXIdPTooManyRequests %s", 429, payload)
}

func (o *UpdateXIDPTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/x/{iid}][%d] updateXIdPTooManyRequests %s", 429, payload)
}

func (o *UpdateXIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateXIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
