// Code generated by go-swagger; DO NOT EDIT.

package keys

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// RotateKeyReader is a Reader for the RotateKey structure.
type RotateKeyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RotateKeyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRotateKeyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewRotateKeyBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewRotateKeyUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRotateKeyForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRotateKeyNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRotateKeyTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewRotateKeyOK creates a RotateKeyOK with default headers values
func NewRotateKeyOK() *RotateKeyOK {
	return &RotateKeyOK{}
}

/*
RotateKeyOK describes a response with status code 200, with default header values.

JWK
*/
type RotateKeyOK struct {
	Payload *models.ServerJWK
}

// IsSuccess returns true when this rotate key o k response has a 2xx status code
func (o *RotateKeyOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this rotate key o k response has a 3xx status code
func (o *RotateKeyOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this rotate key o k response has a 4xx status code
func (o *RotateKeyOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this rotate key o k response has a 5xx status code
func (o *RotateKeyOK) IsServerError() bool {
	return false
}

// IsCode returns true when this rotate key o k response a status code equal to that given
func (o *RotateKeyOK) IsCode(code int) bool {
	return code == 200
}

func (o *RotateKeyOK) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/keys/rotate][%d] rotateKeyOK  %+v", 200, o.Payload)
}

func (o *RotateKeyOK) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/keys/rotate][%d] rotateKeyOK  %+v", 200, o.Payload)
}

func (o *RotateKeyOK) GetPayload() *models.ServerJWK {
	return o.Payload
}

func (o *RotateKeyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ServerJWK)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRotateKeyBadRequest creates a RotateKeyBadRequest with default headers values
func NewRotateKeyBadRequest() *RotateKeyBadRequest {
	return &RotateKeyBadRequest{}
}

/*
RotateKeyBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type RotateKeyBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this rotate key bad request response has a 2xx status code
func (o *RotateKeyBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this rotate key bad request response has a 3xx status code
func (o *RotateKeyBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this rotate key bad request response has a 4xx status code
func (o *RotateKeyBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this rotate key bad request response has a 5xx status code
func (o *RotateKeyBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this rotate key bad request response a status code equal to that given
func (o *RotateKeyBadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *RotateKeyBadRequest) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/keys/rotate][%d] rotateKeyBadRequest  %+v", 400, o.Payload)
}

func (o *RotateKeyBadRequest) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/keys/rotate][%d] rotateKeyBadRequest  %+v", 400, o.Payload)
}

func (o *RotateKeyBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *RotateKeyBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRotateKeyUnauthorized creates a RotateKeyUnauthorized with default headers values
func NewRotateKeyUnauthorized() *RotateKeyUnauthorized {
	return &RotateKeyUnauthorized{}
}

/*
RotateKeyUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type RotateKeyUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this rotate key unauthorized response has a 2xx status code
func (o *RotateKeyUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this rotate key unauthorized response has a 3xx status code
func (o *RotateKeyUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this rotate key unauthorized response has a 4xx status code
func (o *RotateKeyUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this rotate key unauthorized response has a 5xx status code
func (o *RotateKeyUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this rotate key unauthorized response a status code equal to that given
func (o *RotateKeyUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *RotateKeyUnauthorized) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/keys/rotate][%d] rotateKeyUnauthorized  %+v", 401, o.Payload)
}

func (o *RotateKeyUnauthorized) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/keys/rotate][%d] rotateKeyUnauthorized  %+v", 401, o.Payload)
}

func (o *RotateKeyUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *RotateKeyUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRotateKeyForbidden creates a RotateKeyForbidden with default headers values
func NewRotateKeyForbidden() *RotateKeyForbidden {
	return &RotateKeyForbidden{}
}

/*
RotateKeyForbidden describes a response with status code 403, with default header values.

HttpError
*/
type RotateKeyForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this rotate key forbidden response has a 2xx status code
func (o *RotateKeyForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this rotate key forbidden response has a 3xx status code
func (o *RotateKeyForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this rotate key forbidden response has a 4xx status code
func (o *RotateKeyForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this rotate key forbidden response has a 5xx status code
func (o *RotateKeyForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this rotate key forbidden response a status code equal to that given
func (o *RotateKeyForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *RotateKeyForbidden) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/keys/rotate][%d] rotateKeyForbidden  %+v", 403, o.Payload)
}

func (o *RotateKeyForbidden) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/keys/rotate][%d] rotateKeyForbidden  %+v", 403, o.Payload)
}

func (o *RotateKeyForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *RotateKeyForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRotateKeyNotFound creates a RotateKeyNotFound with default headers values
func NewRotateKeyNotFound() *RotateKeyNotFound {
	return &RotateKeyNotFound{}
}

/*
RotateKeyNotFound describes a response with status code 404, with default header values.

HttpError
*/
type RotateKeyNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this rotate key not found response has a 2xx status code
func (o *RotateKeyNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this rotate key not found response has a 3xx status code
func (o *RotateKeyNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this rotate key not found response has a 4xx status code
func (o *RotateKeyNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this rotate key not found response has a 5xx status code
func (o *RotateKeyNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this rotate key not found response a status code equal to that given
func (o *RotateKeyNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *RotateKeyNotFound) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/keys/rotate][%d] rotateKeyNotFound  %+v", 404, o.Payload)
}

func (o *RotateKeyNotFound) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/keys/rotate][%d] rotateKeyNotFound  %+v", 404, o.Payload)
}

func (o *RotateKeyNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *RotateKeyNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRotateKeyTooManyRequests creates a RotateKeyTooManyRequests with default headers values
func NewRotateKeyTooManyRequests() *RotateKeyTooManyRequests {
	return &RotateKeyTooManyRequests{}
}

/*
RotateKeyTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type RotateKeyTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this rotate key too many requests response has a 2xx status code
func (o *RotateKeyTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this rotate key too many requests response has a 3xx status code
func (o *RotateKeyTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this rotate key too many requests response has a 4xx status code
func (o *RotateKeyTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this rotate key too many requests response has a 5xx status code
func (o *RotateKeyTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this rotate key too many requests response a status code equal to that given
func (o *RotateKeyTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *RotateKeyTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/keys/rotate][%d] rotateKeyTooManyRequests  %+v", 429, o.Payload)
}

func (o *RotateKeyTooManyRequests) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/keys/rotate][%d] rotateKeyTooManyRequests  %+v", 429, o.Payload)
}

func (o *RotateKeyTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *RotateKeyTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
