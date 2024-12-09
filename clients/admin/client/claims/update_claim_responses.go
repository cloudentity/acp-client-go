// Code generated by go-swagger; DO NOT EDIT.

package claims

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// UpdateClaimReader is a Reader for the UpdateClaim structure.
type UpdateClaimReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateClaimReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateClaimOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateClaimBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewUpdateClaimUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdateClaimForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateClaimNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewUpdateClaimUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdateClaimTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PUT /claims/{claim}] updateClaim", response, response.Code())
	}
}

// NewUpdateClaimOK creates a UpdateClaimOK with default headers values
func NewUpdateClaimOK() *UpdateClaimOK {
	return &UpdateClaimOK{}
}

/*
UpdateClaimOK describes a response with status code 200, with default header values.

Claim
*/
type UpdateClaimOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.Claim
}

// IsSuccess returns true when this update claim o k response has a 2xx status code
func (o *UpdateClaimOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update claim o k response has a 3xx status code
func (o *UpdateClaimOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update claim o k response has a 4xx status code
func (o *UpdateClaimOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update claim o k response has a 5xx status code
func (o *UpdateClaimOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update claim o k response a status code equal to that given
func (o *UpdateClaimOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update claim o k response
func (o *UpdateClaimOK) Code() int {
	return 200
}

func (o *UpdateClaimOK) Error() string {
	return fmt.Sprintf("[PUT /claims/{claim}][%d] updateClaimOK  %+v", 200, o.Payload)
}

func (o *UpdateClaimOK) String() string {
	return fmt.Sprintf("[PUT /claims/{claim}][%d] updateClaimOK  %+v", 200, o.Payload)
}

func (o *UpdateClaimOK) GetPayload() *models.Claim {
	return o.Payload
}

func (o *UpdateClaimOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.Claim)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateClaimBadRequest creates a UpdateClaimBadRequest with default headers values
func NewUpdateClaimBadRequest() *UpdateClaimBadRequest {
	return &UpdateClaimBadRequest{}
}

/*
UpdateClaimBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type UpdateClaimBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this update claim bad request response has a 2xx status code
func (o *UpdateClaimBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update claim bad request response has a 3xx status code
func (o *UpdateClaimBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update claim bad request response has a 4xx status code
func (o *UpdateClaimBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this update claim bad request response has a 5xx status code
func (o *UpdateClaimBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this update claim bad request response a status code equal to that given
func (o *UpdateClaimBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the update claim bad request response
func (o *UpdateClaimBadRequest) Code() int {
	return 400
}

func (o *UpdateClaimBadRequest) Error() string {
	return fmt.Sprintf("[PUT /claims/{claim}][%d] updateClaimBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateClaimBadRequest) String() string {
	return fmt.Sprintf("[PUT /claims/{claim}][%d] updateClaimBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateClaimBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateClaimBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateClaimUnauthorized creates a UpdateClaimUnauthorized with default headers values
func NewUpdateClaimUnauthorized() *UpdateClaimUnauthorized {
	return &UpdateClaimUnauthorized{}
}

/*
UpdateClaimUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type UpdateClaimUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this update claim unauthorized response has a 2xx status code
func (o *UpdateClaimUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update claim unauthorized response has a 3xx status code
func (o *UpdateClaimUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update claim unauthorized response has a 4xx status code
func (o *UpdateClaimUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this update claim unauthorized response has a 5xx status code
func (o *UpdateClaimUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this update claim unauthorized response a status code equal to that given
func (o *UpdateClaimUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the update claim unauthorized response
func (o *UpdateClaimUnauthorized) Code() int {
	return 401
}

func (o *UpdateClaimUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /claims/{claim}][%d] updateClaimUnauthorized  %+v", 401, o.Payload)
}

func (o *UpdateClaimUnauthorized) String() string {
	return fmt.Sprintf("[PUT /claims/{claim}][%d] updateClaimUnauthorized  %+v", 401, o.Payload)
}

func (o *UpdateClaimUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateClaimUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateClaimForbidden creates a UpdateClaimForbidden with default headers values
func NewUpdateClaimForbidden() *UpdateClaimForbidden {
	return &UpdateClaimForbidden{}
}

/*
UpdateClaimForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdateClaimForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this update claim forbidden response has a 2xx status code
func (o *UpdateClaimForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update claim forbidden response has a 3xx status code
func (o *UpdateClaimForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update claim forbidden response has a 4xx status code
func (o *UpdateClaimForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update claim forbidden response has a 5xx status code
func (o *UpdateClaimForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update claim forbidden response a status code equal to that given
func (o *UpdateClaimForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the update claim forbidden response
func (o *UpdateClaimForbidden) Code() int {
	return 403
}

func (o *UpdateClaimForbidden) Error() string {
	return fmt.Sprintf("[PUT /claims/{claim}][%d] updateClaimForbidden  %+v", 403, o.Payload)
}

func (o *UpdateClaimForbidden) String() string {
	return fmt.Sprintf("[PUT /claims/{claim}][%d] updateClaimForbidden  %+v", 403, o.Payload)
}

func (o *UpdateClaimForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateClaimForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateClaimNotFound creates a UpdateClaimNotFound with default headers values
func NewUpdateClaimNotFound() *UpdateClaimNotFound {
	return &UpdateClaimNotFound{}
}

/*
UpdateClaimNotFound describes a response with status code 404, with default header values.

Not found
*/
type UpdateClaimNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this update claim not found response has a 2xx status code
func (o *UpdateClaimNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update claim not found response has a 3xx status code
func (o *UpdateClaimNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update claim not found response has a 4xx status code
func (o *UpdateClaimNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this update claim not found response has a 5xx status code
func (o *UpdateClaimNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this update claim not found response a status code equal to that given
func (o *UpdateClaimNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the update claim not found response
func (o *UpdateClaimNotFound) Code() int {
	return 404
}

func (o *UpdateClaimNotFound) Error() string {
	return fmt.Sprintf("[PUT /claims/{claim}][%d] updateClaimNotFound  %+v", 404, o.Payload)
}

func (o *UpdateClaimNotFound) String() string {
	return fmt.Sprintf("[PUT /claims/{claim}][%d] updateClaimNotFound  %+v", 404, o.Payload)
}

func (o *UpdateClaimNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateClaimNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateClaimUnprocessableEntity creates a UpdateClaimUnprocessableEntity with default headers values
func NewUpdateClaimUnprocessableEntity() *UpdateClaimUnprocessableEntity {
	return &UpdateClaimUnprocessableEntity{}
}

/*
UpdateClaimUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type UpdateClaimUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this update claim unprocessable entity response has a 2xx status code
func (o *UpdateClaimUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update claim unprocessable entity response has a 3xx status code
func (o *UpdateClaimUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update claim unprocessable entity response has a 4xx status code
func (o *UpdateClaimUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this update claim unprocessable entity response has a 5xx status code
func (o *UpdateClaimUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this update claim unprocessable entity response a status code equal to that given
func (o *UpdateClaimUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the update claim unprocessable entity response
func (o *UpdateClaimUnprocessableEntity) Code() int {
	return 422
}

func (o *UpdateClaimUnprocessableEntity) Error() string {
	return fmt.Sprintf("[PUT /claims/{claim}][%d] updateClaimUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *UpdateClaimUnprocessableEntity) String() string {
	return fmt.Sprintf("[PUT /claims/{claim}][%d] updateClaimUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *UpdateClaimUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateClaimUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateClaimTooManyRequests creates a UpdateClaimTooManyRequests with default headers values
func NewUpdateClaimTooManyRequests() *UpdateClaimTooManyRequests {
	return &UpdateClaimTooManyRequests{}
}

/*
UpdateClaimTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type UpdateClaimTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this update claim too many requests response has a 2xx status code
func (o *UpdateClaimTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update claim too many requests response has a 3xx status code
func (o *UpdateClaimTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update claim too many requests response has a 4xx status code
func (o *UpdateClaimTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update claim too many requests response has a 5xx status code
func (o *UpdateClaimTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update claim too many requests response a status code equal to that given
func (o *UpdateClaimTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the update claim too many requests response
func (o *UpdateClaimTooManyRequests) Code() int {
	return 429
}

func (o *UpdateClaimTooManyRequests) Error() string {
	return fmt.Sprintf("[PUT /claims/{claim}][%d] updateClaimTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateClaimTooManyRequests) String() string {
	return fmt.Sprintf("[PUT /claims/{claim}][%d] updateClaimTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateClaimTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateClaimTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
