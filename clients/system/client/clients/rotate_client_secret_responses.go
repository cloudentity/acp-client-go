// Code generated by go-swagger; DO NOT EDIT.

package clients

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/system/models"
)

// RotateClientSecretReader is a Reader for the RotateClientSecret structure.
type RotateClientSecretReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RotateClientSecretReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRotateClientSecretOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewRotateClientSecretBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewRotateClientSecretUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRotateClientSecretForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRotateClientSecretNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRotateClientSecretTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /client/{cid}/rotateSecret] rotateClientSecret", response, response.Code())
	}
}

// NewRotateClientSecretOK creates a RotateClientSecretOK with default headers values
func NewRotateClientSecretOK() *RotateClientSecretOK {
	return &RotateClientSecretOK{}
}

/*
RotateClientSecretOK describes a response with status code 200, with default header values.

Rotate client secret response
*/
type RotateClientSecretOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.RotateClientSecretResponse
}

// IsSuccess returns true when this rotate client secret o k response has a 2xx status code
func (o *RotateClientSecretOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this rotate client secret o k response has a 3xx status code
func (o *RotateClientSecretOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this rotate client secret o k response has a 4xx status code
func (o *RotateClientSecretOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this rotate client secret o k response has a 5xx status code
func (o *RotateClientSecretOK) IsServerError() bool {
	return false
}

// IsCode returns true when this rotate client secret o k response a status code equal to that given
func (o *RotateClientSecretOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the rotate client secret o k response
func (o *RotateClientSecretOK) Code() int {
	return 200
}

func (o *RotateClientSecretOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /client/{cid}/rotateSecret][%d] rotateClientSecretOK %s", 200, payload)
}

func (o *RotateClientSecretOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /client/{cid}/rotateSecret][%d] rotateClientSecretOK %s", 200, payload)
}

func (o *RotateClientSecretOK) GetPayload() *models.RotateClientSecretResponse {
	return o.Payload
}

func (o *RotateClientSecretOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.RotateClientSecretResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRotateClientSecretBadRequest creates a RotateClientSecretBadRequest with default headers values
func NewRotateClientSecretBadRequest() *RotateClientSecretBadRequest {
	return &RotateClientSecretBadRequest{}
}

/*
RotateClientSecretBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type RotateClientSecretBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this rotate client secret bad request response has a 2xx status code
func (o *RotateClientSecretBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this rotate client secret bad request response has a 3xx status code
func (o *RotateClientSecretBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this rotate client secret bad request response has a 4xx status code
func (o *RotateClientSecretBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this rotate client secret bad request response has a 5xx status code
func (o *RotateClientSecretBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this rotate client secret bad request response a status code equal to that given
func (o *RotateClientSecretBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the rotate client secret bad request response
func (o *RotateClientSecretBadRequest) Code() int {
	return 400
}

func (o *RotateClientSecretBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /client/{cid}/rotateSecret][%d] rotateClientSecretBadRequest %s", 400, payload)
}

func (o *RotateClientSecretBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /client/{cid}/rotateSecret][%d] rotateClientSecretBadRequest %s", 400, payload)
}

func (o *RotateClientSecretBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *RotateClientSecretBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRotateClientSecretUnauthorized creates a RotateClientSecretUnauthorized with default headers values
func NewRotateClientSecretUnauthorized() *RotateClientSecretUnauthorized {
	return &RotateClientSecretUnauthorized{}
}

/*
RotateClientSecretUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type RotateClientSecretUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this rotate client secret unauthorized response has a 2xx status code
func (o *RotateClientSecretUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this rotate client secret unauthorized response has a 3xx status code
func (o *RotateClientSecretUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this rotate client secret unauthorized response has a 4xx status code
func (o *RotateClientSecretUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this rotate client secret unauthorized response has a 5xx status code
func (o *RotateClientSecretUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this rotate client secret unauthorized response a status code equal to that given
func (o *RotateClientSecretUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the rotate client secret unauthorized response
func (o *RotateClientSecretUnauthorized) Code() int {
	return 401
}

func (o *RotateClientSecretUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /client/{cid}/rotateSecret][%d] rotateClientSecretUnauthorized %s", 401, payload)
}

func (o *RotateClientSecretUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /client/{cid}/rotateSecret][%d] rotateClientSecretUnauthorized %s", 401, payload)
}

func (o *RotateClientSecretUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *RotateClientSecretUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRotateClientSecretForbidden creates a RotateClientSecretForbidden with default headers values
func NewRotateClientSecretForbidden() *RotateClientSecretForbidden {
	return &RotateClientSecretForbidden{}
}

/*
RotateClientSecretForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type RotateClientSecretForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this rotate client secret forbidden response has a 2xx status code
func (o *RotateClientSecretForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this rotate client secret forbidden response has a 3xx status code
func (o *RotateClientSecretForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this rotate client secret forbidden response has a 4xx status code
func (o *RotateClientSecretForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this rotate client secret forbidden response has a 5xx status code
func (o *RotateClientSecretForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this rotate client secret forbidden response a status code equal to that given
func (o *RotateClientSecretForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the rotate client secret forbidden response
func (o *RotateClientSecretForbidden) Code() int {
	return 403
}

func (o *RotateClientSecretForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /client/{cid}/rotateSecret][%d] rotateClientSecretForbidden %s", 403, payload)
}

func (o *RotateClientSecretForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /client/{cid}/rotateSecret][%d] rotateClientSecretForbidden %s", 403, payload)
}

func (o *RotateClientSecretForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *RotateClientSecretForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRotateClientSecretNotFound creates a RotateClientSecretNotFound with default headers values
func NewRotateClientSecretNotFound() *RotateClientSecretNotFound {
	return &RotateClientSecretNotFound{}
}

/*
RotateClientSecretNotFound describes a response with status code 404, with default header values.

Not found
*/
type RotateClientSecretNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this rotate client secret not found response has a 2xx status code
func (o *RotateClientSecretNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this rotate client secret not found response has a 3xx status code
func (o *RotateClientSecretNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this rotate client secret not found response has a 4xx status code
func (o *RotateClientSecretNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this rotate client secret not found response has a 5xx status code
func (o *RotateClientSecretNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this rotate client secret not found response a status code equal to that given
func (o *RotateClientSecretNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the rotate client secret not found response
func (o *RotateClientSecretNotFound) Code() int {
	return 404
}

func (o *RotateClientSecretNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /client/{cid}/rotateSecret][%d] rotateClientSecretNotFound %s", 404, payload)
}

func (o *RotateClientSecretNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /client/{cid}/rotateSecret][%d] rotateClientSecretNotFound %s", 404, payload)
}

func (o *RotateClientSecretNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *RotateClientSecretNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRotateClientSecretTooManyRequests creates a RotateClientSecretTooManyRequests with default headers values
func NewRotateClientSecretTooManyRequests() *RotateClientSecretTooManyRequests {
	return &RotateClientSecretTooManyRequests{}
}

/*
RotateClientSecretTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type RotateClientSecretTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this rotate client secret too many requests response has a 2xx status code
func (o *RotateClientSecretTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this rotate client secret too many requests response has a 3xx status code
func (o *RotateClientSecretTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this rotate client secret too many requests response has a 4xx status code
func (o *RotateClientSecretTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this rotate client secret too many requests response has a 5xx status code
func (o *RotateClientSecretTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this rotate client secret too many requests response a status code equal to that given
func (o *RotateClientSecretTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the rotate client secret too many requests response
func (o *RotateClientSecretTooManyRequests) Code() int {
	return 429
}

func (o *RotateClientSecretTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /client/{cid}/rotateSecret][%d] rotateClientSecretTooManyRequests %s", 429, payload)
}

func (o *RotateClientSecretTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /client/{cid}/rotateSecret][%d] rotateClientSecretTooManyRequests %s", 429, payload)
}

func (o *RotateClientSecretTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *RotateClientSecretTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
