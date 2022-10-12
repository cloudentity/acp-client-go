// Code generated by go-swagger; DO NOT EDIT.

package transient_otp

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/public/models"
)

// GetTransientOTPReader is a Reader for the GetTransientOTP structure.
type GetTransientOTPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetTransientOTPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetTransientOTPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetTransientOTPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetTransientOTPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetTransientOTPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewGetTransientOTPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetTransientOTPOK creates a GetTransientOTPOK with default headers values
func NewGetTransientOTPOK() *GetTransientOTPOK {
	return &GetTransientOTPOK{}
}

/*
GetTransientOTPOK describes a response with status code 200, with default header values.

Transient OTP
*/
type GetTransientOTPOK struct {
	Payload *models.TransientOTPResponse
}

// IsSuccess returns true when this get transient o t p o k response has a 2xx status code
func (o *GetTransientOTPOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get transient o t p o k response has a 3xx status code
func (o *GetTransientOTPOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get transient o t p o k response has a 4xx status code
func (o *GetTransientOTPOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get transient o t p o k response has a 5xx status code
func (o *GetTransientOTPOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get transient o t p o k response a status code equal to that given
func (o *GetTransientOTPOK) IsCode(code int) bool {
	return code == 200
}

func (o *GetTransientOTPOK) Error() string {
	return fmt.Sprintf("[GET /authn/otp/transient/{otpID}][%d] getTransientOTPOK  %+v", 200, o.Payload)
}

func (o *GetTransientOTPOK) String() string {
	return fmt.Sprintf("[GET /authn/otp/transient/{otpID}][%d] getTransientOTPOK  %+v", 200, o.Payload)
}

func (o *GetTransientOTPOK) GetPayload() *models.TransientOTPResponse {
	return o.Payload
}

func (o *GetTransientOTPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.TransientOTPResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetTransientOTPUnauthorized creates a GetTransientOTPUnauthorized with default headers values
func NewGetTransientOTPUnauthorized() *GetTransientOTPUnauthorized {
	return &GetTransientOTPUnauthorized{}
}

/*
GetTransientOTPUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type GetTransientOTPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get transient o t p unauthorized response has a 2xx status code
func (o *GetTransientOTPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get transient o t p unauthorized response has a 3xx status code
func (o *GetTransientOTPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get transient o t p unauthorized response has a 4xx status code
func (o *GetTransientOTPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get transient o t p unauthorized response has a 5xx status code
func (o *GetTransientOTPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get transient o t p unauthorized response a status code equal to that given
func (o *GetTransientOTPUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *GetTransientOTPUnauthorized) Error() string {
	return fmt.Sprintf("[GET /authn/otp/transient/{otpID}][%d] getTransientOTPUnauthorized  %+v", 401, o.Payload)
}

func (o *GetTransientOTPUnauthorized) String() string {
	return fmt.Sprintf("[GET /authn/otp/transient/{otpID}][%d] getTransientOTPUnauthorized  %+v", 401, o.Payload)
}

func (o *GetTransientOTPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetTransientOTPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetTransientOTPForbidden creates a GetTransientOTPForbidden with default headers values
func NewGetTransientOTPForbidden() *GetTransientOTPForbidden {
	return &GetTransientOTPForbidden{}
}

/*
GetTransientOTPForbidden describes a response with status code 403, with default header values.

HttpError
*/
type GetTransientOTPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get transient o t p forbidden response has a 2xx status code
func (o *GetTransientOTPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get transient o t p forbidden response has a 3xx status code
func (o *GetTransientOTPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get transient o t p forbidden response has a 4xx status code
func (o *GetTransientOTPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get transient o t p forbidden response has a 5xx status code
func (o *GetTransientOTPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get transient o t p forbidden response a status code equal to that given
func (o *GetTransientOTPForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *GetTransientOTPForbidden) Error() string {
	return fmt.Sprintf("[GET /authn/otp/transient/{otpID}][%d] getTransientOTPForbidden  %+v", 403, o.Payload)
}

func (o *GetTransientOTPForbidden) String() string {
	return fmt.Sprintf("[GET /authn/otp/transient/{otpID}][%d] getTransientOTPForbidden  %+v", 403, o.Payload)
}

func (o *GetTransientOTPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetTransientOTPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetTransientOTPNotFound creates a GetTransientOTPNotFound with default headers values
func NewGetTransientOTPNotFound() *GetTransientOTPNotFound {
	return &GetTransientOTPNotFound{}
}

/*
GetTransientOTPNotFound describes a response with status code 404, with default header values.

HttpError
*/
type GetTransientOTPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get transient o t p not found response has a 2xx status code
func (o *GetTransientOTPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get transient o t p not found response has a 3xx status code
func (o *GetTransientOTPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get transient o t p not found response has a 4xx status code
func (o *GetTransientOTPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get transient o t p not found response has a 5xx status code
func (o *GetTransientOTPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get transient o t p not found response a status code equal to that given
func (o *GetTransientOTPNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *GetTransientOTPNotFound) Error() string {
	return fmt.Sprintf("[GET /authn/otp/transient/{otpID}][%d] getTransientOTPNotFound  %+v", 404, o.Payload)
}

func (o *GetTransientOTPNotFound) String() string {
	return fmt.Sprintf("[GET /authn/otp/transient/{otpID}][%d] getTransientOTPNotFound  %+v", 404, o.Payload)
}

func (o *GetTransientOTPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetTransientOTPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetTransientOTPUnprocessableEntity creates a GetTransientOTPUnprocessableEntity with default headers values
func NewGetTransientOTPUnprocessableEntity() *GetTransientOTPUnprocessableEntity {
	return &GetTransientOTPUnprocessableEntity{}
}

/*
GetTransientOTPUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type GetTransientOTPUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this get transient o t p unprocessable entity response has a 2xx status code
func (o *GetTransientOTPUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get transient o t p unprocessable entity response has a 3xx status code
func (o *GetTransientOTPUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get transient o t p unprocessable entity response has a 4xx status code
func (o *GetTransientOTPUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this get transient o t p unprocessable entity response has a 5xx status code
func (o *GetTransientOTPUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this get transient o t p unprocessable entity response a status code equal to that given
func (o *GetTransientOTPUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

func (o *GetTransientOTPUnprocessableEntity) Error() string {
	return fmt.Sprintf("[GET /authn/otp/transient/{otpID}][%d] getTransientOTPUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *GetTransientOTPUnprocessableEntity) String() string {
	return fmt.Sprintf("[GET /authn/otp/transient/{otpID}][%d] getTransientOTPUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *GetTransientOTPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetTransientOTPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
