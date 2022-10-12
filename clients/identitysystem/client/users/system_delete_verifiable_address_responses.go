// Code generated by go-swagger; DO NOT EDIT.

package users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identitysystem/models"
)

// SystemDeleteVerifiableAddressReader is a Reader for the SystemDeleteVerifiableAddress structure.
type SystemDeleteVerifiableAddressReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SystemDeleteVerifiableAddressReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewSystemDeleteVerifiableAddressNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewSystemDeleteVerifiableAddressUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSystemDeleteVerifiableAddressForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSystemDeleteVerifiableAddressNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewSystemDeleteVerifiableAddressPreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSystemDeleteVerifiableAddressTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewSystemDeleteVerifiableAddressNoContent creates a SystemDeleteVerifiableAddressNoContent with default headers values
func NewSystemDeleteVerifiableAddressNoContent() *SystemDeleteVerifiableAddressNoContent {
	return &SystemDeleteVerifiableAddressNoContent{}
}

/*
SystemDeleteVerifiableAddressNoContent describes a response with status code 204, with default header values.

Deletes a verifiable address from the user account
*/
type SystemDeleteVerifiableAddressNoContent struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string
}

// IsSuccess returns true when this system delete verifiable address no content response has a 2xx status code
func (o *SystemDeleteVerifiableAddressNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this system delete verifiable address no content response has a 3xx status code
func (o *SystemDeleteVerifiableAddressNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system delete verifiable address no content response has a 4xx status code
func (o *SystemDeleteVerifiableAddressNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this system delete verifiable address no content response has a 5xx status code
func (o *SystemDeleteVerifiableAddressNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this system delete verifiable address no content response a status code equal to that given
func (o *SystemDeleteVerifiableAddressNoContent) IsCode(code int) bool {
	return code == 204
}

func (o *SystemDeleteVerifiableAddressNoContent) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/addresses/remove][%d] systemDeleteVerifiableAddressNoContent ", 204)
}

func (o *SystemDeleteVerifiableAddressNoContent) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/addresses/remove][%d] systemDeleteVerifiableAddressNoContent ", 204)
}

func (o *SystemDeleteVerifiableAddressNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	return nil
}

// NewSystemDeleteVerifiableAddressUnauthorized creates a SystemDeleteVerifiableAddressUnauthorized with default headers values
func NewSystemDeleteVerifiableAddressUnauthorized() *SystemDeleteVerifiableAddressUnauthorized {
	return &SystemDeleteVerifiableAddressUnauthorized{}
}

/*
SystemDeleteVerifiableAddressUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type SystemDeleteVerifiableAddressUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this system delete verifiable address unauthorized response has a 2xx status code
func (o *SystemDeleteVerifiableAddressUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system delete verifiable address unauthorized response has a 3xx status code
func (o *SystemDeleteVerifiableAddressUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system delete verifiable address unauthorized response has a 4xx status code
func (o *SystemDeleteVerifiableAddressUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this system delete verifiable address unauthorized response has a 5xx status code
func (o *SystemDeleteVerifiableAddressUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this system delete verifiable address unauthorized response a status code equal to that given
func (o *SystemDeleteVerifiableAddressUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *SystemDeleteVerifiableAddressUnauthorized) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/addresses/remove][%d] systemDeleteVerifiableAddressUnauthorized  %+v", 401, o.Payload)
}

func (o *SystemDeleteVerifiableAddressUnauthorized) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/addresses/remove][%d] systemDeleteVerifiableAddressUnauthorized  %+v", 401, o.Payload)
}

func (o *SystemDeleteVerifiableAddressUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemDeleteVerifiableAddressUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemDeleteVerifiableAddressForbidden creates a SystemDeleteVerifiableAddressForbidden with default headers values
func NewSystemDeleteVerifiableAddressForbidden() *SystemDeleteVerifiableAddressForbidden {
	return &SystemDeleteVerifiableAddressForbidden{}
}

/*
SystemDeleteVerifiableAddressForbidden describes a response with status code 403, with default header values.

HttpError
*/
type SystemDeleteVerifiableAddressForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this system delete verifiable address forbidden response has a 2xx status code
func (o *SystemDeleteVerifiableAddressForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system delete verifiable address forbidden response has a 3xx status code
func (o *SystemDeleteVerifiableAddressForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system delete verifiable address forbidden response has a 4xx status code
func (o *SystemDeleteVerifiableAddressForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this system delete verifiable address forbidden response has a 5xx status code
func (o *SystemDeleteVerifiableAddressForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this system delete verifiable address forbidden response a status code equal to that given
func (o *SystemDeleteVerifiableAddressForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *SystemDeleteVerifiableAddressForbidden) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/addresses/remove][%d] systemDeleteVerifiableAddressForbidden  %+v", 403, o.Payload)
}

func (o *SystemDeleteVerifiableAddressForbidden) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/addresses/remove][%d] systemDeleteVerifiableAddressForbidden  %+v", 403, o.Payload)
}

func (o *SystemDeleteVerifiableAddressForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemDeleteVerifiableAddressForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemDeleteVerifiableAddressNotFound creates a SystemDeleteVerifiableAddressNotFound with default headers values
func NewSystemDeleteVerifiableAddressNotFound() *SystemDeleteVerifiableAddressNotFound {
	return &SystemDeleteVerifiableAddressNotFound{}
}

/*
SystemDeleteVerifiableAddressNotFound describes a response with status code 404, with default header values.

HttpError
*/
type SystemDeleteVerifiableAddressNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this system delete verifiable address not found response has a 2xx status code
func (o *SystemDeleteVerifiableAddressNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system delete verifiable address not found response has a 3xx status code
func (o *SystemDeleteVerifiableAddressNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system delete verifiable address not found response has a 4xx status code
func (o *SystemDeleteVerifiableAddressNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this system delete verifiable address not found response has a 5xx status code
func (o *SystemDeleteVerifiableAddressNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this system delete verifiable address not found response a status code equal to that given
func (o *SystemDeleteVerifiableAddressNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *SystemDeleteVerifiableAddressNotFound) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/addresses/remove][%d] systemDeleteVerifiableAddressNotFound  %+v", 404, o.Payload)
}

func (o *SystemDeleteVerifiableAddressNotFound) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/addresses/remove][%d] systemDeleteVerifiableAddressNotFound  %+v", 404, o.Payload)
}

func (o *SystemDeleteVerifiableAddressNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemDeleteVerifiableAddressNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemDeleteVerifiableAddressPreconditionFailed creates a SystemDeleteVerifiableAddressPreconditionFailed with default headers values
func NewSystemDeleteVerifiableAddressPreconditionFailed() *SystemDeleteVerifiableAddressPreconditionFailed {
	return &SystemDeleteVerifiableAddressPreconditionFailed{}
}

/*
SystemDeleteVerifiableAddressPreconditionFailed describes a response with status code 412, with default header values.

HttpError
*/
type SystemDeleteVerifiableAddressPreconditionFailed struct {
	Payload *models.Error
}

// IsSuccess returns true when this system delete verifiable address precondition failed response has a 2xx status code
func (o *SystemDeleteVerifiableAddressPreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system delete verifiable address precondition failed response has a 3xx status code
func (o *SystemDeleteVerifiableAddressPreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system delete verifiable address precondition failed response has a 4xx status code
func (o *SystemDeleteVerifiableAddressPreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this system delete verifiable address precondition failed response has a 5xx status code
func (o *SystemDeleteVerifiableAddressPreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this system delete verifiable address precondition failed response a status code equal to that given
func (o *SystemDeleteVerifiableAddressPreconditionFailed) IsCode(code int) bool {
	return code == 412
}

func (o *SystemDeleteVerifiableAddressPreconditionFailed) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/addresses/remove][%d] systemDeleteVerifiableAddressPreconditionFailed  %+v", 412, o.Payload)
}

func (o *SystemDeleteVerifiableAddressPreconditionFailed) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/addresses/remove][%d] systemDeleteVerifiableAddressPreconditionFailed  %+v", 412, o.Payload)
}

func (o *SystemDeleteVerifiableAddressPreconditionFailed) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemDeleteVerifiableAddressPreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemDeleteVerifiableAddressTooManyRequests creates a SystemDeleteVerifiableAddressTooManyRequests with default headers values
func NewSystemDeleteVerifiableAddressTooManyRequests() *SystemDeleteVerifiableAddressTooManyRequests {
	return &SystemDeleteVerifiableAddressTooManyRequests{}
}

/*
SystemDeleteVerifiableAddressTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type SystemDeleteVerifiableAddressTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this system delete verifiable address too many requests response has a 2xx status code
func (o *SystemDeleteVerifiableAddressTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system delete verifiable address too many requests response has a 3xx status code
func (o *SystemDeleteVerifiableAddressTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system delete verifiable address too many requests response has a 4xx status code
func (o *SystemDeleteVerifiableAddressTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this system delete verifiable address too many requests response has a 5xx status code
func (o *SystemDeleteVerifiableAddressTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this system delete verifiable address too many requests response a status code equal to that given
func (o *SystemDeleteVerifiableAddressTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *SystemDeleteVerifiableAddressTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/addresses/remove][%d] systemDeleteVerifiableAddressTooManyRequests  %+v", 429, o.Payload)
}

func (o *SystemDeleteVerifiableAddressTooManyRequests) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/addresses/remove][%d] systemDeleteVerifiableAddressTooManyRequests  %+v", 429, o.Payload)
}

func (o *SystemDeleteVerifiableAddressTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemDeleteVerifiableAddressTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
