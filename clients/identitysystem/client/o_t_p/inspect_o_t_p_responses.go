// Code generated by go-swagger; DO NOT EDIT.

package o_t_p

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identitysystem/models"
)

// InspectOTPReader is a Reader for the InspectOTP structure.
type InspectOTPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *InspectOTPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewInspectOTPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewInspectOTPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewInspectOTPPreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewInspectOTPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /system/pools/{ipID}/user/otp/inspect] inspectOTP", response, response.Code())
	}
}

// NewInspectOTPOK creates a InspectOTPOK with default headers values
func NewInspectOTPOK() *InspectOTPOK {
	return &InspectOTPOK{}
}

/*
InspectOTPOK describes a response with status code 200, with default header values.

OTP
*/
type InspectOTPOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.InspectOTPUserOperationalData
}

// IsSuccess returns true when this inspect o t p o k response has a 2xx status code
func (o *InspectOTPOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this inspect o t p o k response has a 3xx status code
func (o *InspectOTPOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this inspect o t p o k response has a 4xx status code
func (o *InspectOTPOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this inspect o t p o k response has a 5xx status code
func (o *InspectOTPOK) IsServerError() bool {
	return false
}

// IsCode returns true when this inspect o t p o k response a status code equal to that given
func (o *InspectOTPOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the inspect o t p o k response
func (o *InspectOTPOK) Code() int {
	return 200
}

func (o *InspectOTPOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/otp/inspect][%d] inspectOTPOK %s", 200, payload)
}

func (o *InspectOTPOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/otp/inspect][%d] inspectOTPOK %s", 200, payload)
}

func (o *InspectOTPOK) GetPayload() *models.InspectOTPUserOperationalData {
	return o.Payload
}

func (o *InspectOTPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.InspectOTPUserOperationalData)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewInspectOTPUnauthorized creates a InspectOTPUnauthorized with default headers values
func NewInspectOTPUnauthorized() *InspectOTPUnauthorized {
	return &InspectOTPUnauthorized{}
}

/*
InspectOTPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type InspectOTPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this inspect o t p unauthorized response has a 2xx status code
func (o *InspectOTPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this inspect o t p unauthorized response has a 3xx status code
func (o *InspectOTPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this inspect o t p unauthorized response has a 4xx status code
func (o *InspectOTPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this inspect o t p unauthorized response has a 5xx status code
func (o *InspectOTPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this inspect o t p unauthorized response a status code equal to that given
func (o *InspectOTPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the inspect o t p unauthorized response
func (o *InspectOTPUnauthorized) Code() int {
	return 401
}

func (o *InspectOTPUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/otp/inspect][%d] inspectOTPUnauthorized %s", 401, payload)
}

func (o *InspectOTPUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/otp/inspect][%d] inspectOTPUnauthorized %s", 401, payload)
}

func (o *InspectOTPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *InspectOTPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewInspectOTPPreconditionFailed creates a InspectOTPPreconditionFailed with default headers values
func NewInspectOTPPreconditionFailed() *InspectOTPPreconditionFailed {
	return &InspectOTPPreconditionFailed{}
}

/*
InspectOTPPreconditionFailed describes a response with status code 412, with default header values.

Payload too large
*/
type InspectOTPPreconditionFailed struct {
	Payload *models.Error
}

// IsSuccess returns true when this inspect o t p precondition failed response has a 2xx status code
func (o *InspectOTPPreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this inspect o t p precondition failed response has a 3xx status code
func (o *InspectOTPPreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this inspect o t p precondition failed response has a 4xx status code
func (o *InspectOTPPreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this inspect o t p precondition failed response has a 5xx status code
func (o *InspectOTPPreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this inspect o t p precondition failed response a status code equal to that given
func (o *InspectOTPPreconditionFailed) IsCode(code int) bool {
	return code == 412
}

// Code gets the status code for the inspect o t p precondition failed response
func (o *InspectOTPPreconditionFailed) Code() int {
	return 412
}

func (o *InspectOTPPreconditionFailed) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/otp/inspect][%d] inspectOTPPreconditionFailed %s", 412, payload)
}

func (o *InspectOTPPreconditionFailed) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/otp/inspect][%d] inspectOTPPreconditionFailed %s", 412, payload)
}

func (o *InspectOTPPreconditionFailed) GetPayload() *models.Error {
	return o.Payload
}

func (o *InspectOTPPreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewInspectOTPUnprocessableEntity creates a InspectOTPUnprocessableEntity with default headers values
func NewInspectOTPUnprocessableEntity() *InspectOTPUnprocessableEntity {
	return &InspectOTPUnprocessableEntity{}
}

/*
InspectOTPUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type InspectOTPUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this inspect o t p unprocessable entity response has a 2xx status code
func (o *InspectOTPUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this inspect o t p unprocessable entity response has a 3xx status code
func (o *InspectOTPUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this inspect o t p unprocessable entity response has a 4xx status code
func (o *InspectOTPUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this inspect o t p unprocessable entity response has a 5xx status code
func (o *InspectOTPUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this inspect o t p unprocessable entity response a status code equal to that given
func (o *InspectOTPUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the inspect o t p unprocessable entity response
func (o *InspectOTPUnprocessableEntity) Code() int {
	return 422
}

func (o *InspectOTPUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/otp/inspect][%d] inspectOTPUnprocessableEntity %s", 422, payload)
}

func (o *InspectOTPUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/otp/inspect][%d] inspectOTPUnprocessableEntity %s", 422, payload)
}

func (o *InspectOTPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *InspectOTPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
