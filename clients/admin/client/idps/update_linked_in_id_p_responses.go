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

// UpdateLinkedInIDPReader is a Reader for the UpdateLinkedInIDP structure.
type UpdateLinkedInIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateLinkedInIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateLinkedInIDPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateLinkedInIDPBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewUpdateLinkedInIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdateLinkedInIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateLinkedInIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewUpdateLinkedInIDPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdateLinkedInIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PUT /servers/{wid}/idps/linkedin/{iid}] updateLinkedInIDP", response, response.Code())
	}
}

// NewUpdateLinkedInIDPOK creates a UpdateLinkedInIDPOK with default headers values
func NewUpdateLinkedInIDPOK() *UpdateLinkedInIDPOK {
	return &UpdateLinkedInIDPOK{}
}

/*
UpdateLinkedInIDPOK describes a response with status code 200, with default header values.

LinkedInIDP
*/
type UpdateLinkedInIDPOK struct {
	Payload *models.LinkedInIDP
}

// IsSuccess returns true when this update linked in Id p o k response has a 2xx status code
func (o *UpdateLinkedInIDPOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update linked in Id p o k response has a 3xx status code
func (o *UpdateLinkedInIDPOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update linked in Id p o k response has a 4xx status code
func (o *UpdateLinkedInIDPOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update linked in Id p o k response has a 5xx status code
func (o *UpdateLinkedInIDPOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update linked in Id p o k response a status code equal to that given
func (o *UpdateLinkedInIDPOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update linked in Id p o k response
func (o *UpdateLinkedInIDPOK) Code() int {
	return 200
}

func (o *UpdateLinkedInIDPOK) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/linkedin/{iid}][%d] updateLinkedInIdPOK  %+v", 200, o.Payload)
}

func (o *UpdateLinkedInIDPOK) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/linkedin/{iid}][%d] updateLinkedInIdPOK  %+v", 200, o.Payload)
}

func (o *UpdateLinkedInIDPOK) GetPayload() *models.LinkedInIDP {
	return o.Payload
}

func (o *UpdateLinkedInIDPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.LinkedInIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateLinkedInIDPBadRequest creates a UpdateLinkedInIDPBadRequest with default headers values
func NewUpdateLinkedInIDPBadRequest() *UpdateLinkedInIDPBadRequest {
	return &UpdateLinkedInIDPBadRequest{}
}

/*
UpdateLinkedInIDPBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type UpdateLinkedInIDPBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this update linked in Id p bad request response has a 2xx status code
func (o *UpdateLinkedInIDPBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update linked in Id p bad request response has a 3xx status code
func (o *UpdateLinkedInIDPBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update linked in Id p bad request response has a 4xx status code
func (o *UpdateLinkedInIDPBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this update linked in Id p bad request response has a 5xx status code
func (o *UpdateLinkedInIDPBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this update linked in Id p bad request response a status code equal to that given
func (o *UpdateLinkedInIDPBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the update linked in Id p bad request response
func (o *UpdateLinkedInIDPBadRequest) Code() int {
	return 400
}

func (o *UpdateLinkedInIDPBadRequest) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/linkedin/{iid}][%d] updateLinkedInIdPBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateLinkedInIDPBadRequest) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/linkedin/{iid}][%d] updateLinkedInIdPBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateLinkedInIDPBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateLinkedInIDPBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateLinkedInIDPUnauthorized creates a UpdateLinkedInIDPUnauthorized with default headers values
func NewUpdateLinkedInIDPUnauthorized() *UpdateLinkedInIDPUnauthorized {
	return &UpdateLinkedInIDPUnauthorized{}
}

/*
UpdateLinkedInIDPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type UpdateLinkedInIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this update linked in Id p unauthorized response has a 2xx status code
func (o *UpdateLinkedInIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update linked in Id p unauthorized response has a 3xx status code
func (o *UpdateLinkedInIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update linked in Id p unauthorized response has a 4xx status code
func (o *UpdateLinkedInIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this update linked in Id p unauthorized response has a 5xx status code
func (o *UpdateLinkedInIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this update linked in Id p unauthorized response a status code equal to that given
func (o *UpdateLinkedInIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the update linked in Id p unauthorized response
func (o *UpdateLinkedInIDPUnauthorized) Code() int {
	return 401
}

func (o *UpdateLinkedInIDPUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/linkedin/{iid}][%d] updateLinkedInIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *UpdateLinkedInIDPUnauthorized) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/linkedin/{iid}][%d] updateLinkedInIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *UpdateLinkedInIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateLinkedInIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateLinkedInIDPForbidden creates a UpdateLinkedInIDPForbidden with default headers values
func NewUpdateLinkedInIDPForbidden() *UpdateLinkedInIDPForbidden {
	return &UpdateLinkedInIDPForbidden{}
}

/*
UpdateLinkedInIDPForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdateLinkedInIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this update linked in Id p forbidden response has a 2xx status code
func (o *UpdateLinkedInIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update linked in Id p forbidden response has a 3xx status code
func (o *UpdateLinkedInIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update linked in Id p forbidden response has a 4xx status code
func (o *UpdateLinkedInIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update linked in Id p forbidden response has a 5xx status code
func (o *UpdateLinkedInIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update linked in Id p forbidden response a status code equal to that given
func (o *UpdateLinkedInIDPForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the update linked in Id p forbidden response
func (o *UpdateLinkedInIDPForbidden) Code() int {
	return 403
}

func (o *UpdateLinkedInIDPForbidden) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/linkedin/{iid}][%d] updateLinkedInIdPForbidden  %+v", 403, o.Payload)
}

func (o *UpdateLinkedInIDPForbidden) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/linkedin/{iid}][%d] updateLinkedInIdPForbidden  %+v", 403, o.Payload)
}

func (o *UpdateLinkedInIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateLinkedInIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateLinkedInIDPNotFound creates a UpdateLinkedInIDPNotFound with default headers values
func NewUpdateLinkedInIDPNotFound() *UpdateLinkedInIDPNotFound {
	return &UpdateLinkedInIDPNotFound{}
}

/*
UpdateLinkedInIDPNotFound describes a response with status code 404, with default header values.

Not found
*/
type UpdateLinkedInIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this update linked in Id p not found response has a 2xx status code
func (o *UpdateLinkedInIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update linked in Id p not found response has a 3xx status code
func (o *UpdateLinkedInIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update linked in Id p not found response has a 4xx status code
func (o *UpdateLinkedInIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this update linked in Id p not found response has a 5xx status code
func (o *UpdateLinkedInIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this update linked in Id p not found response a status code equal to that given
func (o *UpdateLinkedInIDPNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the update linked in Id p not found response
func (o *UpdateLinkedInIDPNotFound) Code() int {
	return 404
}

func (o *UpdateLinkedInIDPNotFound) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/linkedin/{iid}][%d] updateLinkedInIdPNotFound  %+v", 404, o.Payload)
}

func (o *UpdateLinkedInIDPNotFound) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/linkedin/{iid}][%d] updateLinkedInIdPNotFound  %+v", 404, o.Payload)
}

func (o *UpdateLinkedInIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateLinkedInIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateLinkedInIDPUnprocessableEntity creates a UpdateLinkedInIDPUnprocessableEntity with default headers values
func NewUpdateLinkedInIDPUnprocessableEntity() *UpdateLinkedInIDPUnprocessableEntity {
	return &UpdateLinkedInIDPUnprocessableEntity{}
}

/*
UpdateLinkedInIDPUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type UpdateLinkedInIDPUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this update linked in Id p unprocessable entity response has a 2xx status code
func (o *UpdateLinkedInIDPUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update linked in Id p unprocessable entity response has a 3xx status code
func (o *UpdateLinkedInIDPUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update linked in Id p unprocessable entity response has a 4xx status code
func (o *UpdateLinkedInIDPUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this update linked in Id p unprocessable entity response has a 5xx status code
func (o *UpdateLinkedInIDPUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this update linked in Id p unprocessable entity response a status code equal to that given
func (o *UpdateLinkedInIDPUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the update linked in Id p unprocessable entity response
func (o *UpdateLinkedInIDPUnprocessableEntity) Code() int {
	return 422
}

func (o *UpdateLinkedInIDPUnprocessableEntity) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/linkedin/{iid}][%d] updateLinkedInIdPUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *UpdateLinkedInIDPUnprocessableEntity) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/linkedin/{iid}][%d] updateLinkedInIdPUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *UpdateLinkedInIDPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateLinkedInIDPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateLinkedInIDPTooManyRequests creates a UpdateLinkedInIDPTooManyRequests with default headers values
func NewUpdateLinkedInIDPTooManyRequests() *UpdateLinkedInIDPTooManyRequests {
	return &UpdateLinkedInIDPTooManyRequests{}
}

/*
UpdateLinkedInIDPTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type UpdateLinkedInIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this update linked in Id p too many requests response has a 2xx status code
func (o *UpdateLinkedInIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update linked in Id p too many requests response has a 3xx status code
func (o *UpdateLinkedInIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update linked in Id p too many requests response has a 4xx status code
func (o *UpdateLinkedInIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update linked in Id p too many requests response has a 5xx status code
func (o *UpdateLinkedInIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update linked in Id p too many requests response a status code equal to that given
func (o *UpdateLinkedInIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the update linked in Id p too many requests response
func (o *UpdateLinkedInIDPTooManyRequests) Code() int {
	return 429
}

func (o *UpdateLinkedInIDPTooManyRequests) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/linkedin/{iid}][%d] updateLinkedInIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateLinkedInIDPTooManyRequests) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/linkedin/{iid}][%d] updateLinkedInIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateLinkedInIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateLinkedInIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
