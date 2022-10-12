// Code generated by go-swagger; DO NOT EDIT.

package mfa_methods

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// TestMFAMethodReader is a Reader for the TestMFAMethod structure.
type TestMFAMethodReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *TestMFAMethodReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewTestMFAMethodOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewTestMFAMethodBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewTestMFAMethodUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewTestMFAMethodForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewTestMFAMethodNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewTestMFAMethodTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewTestMFAMethodOK creates a TestMFAMethodOK with default headers values
func NewTestMFAMethodOK() *TestMFAMethodOK {
	return &TestMFAMethodOK{}
}

/*
TestMFAMethodOK describes a response with status code 200, with default header values.

	MFA OTP message sent
*/
type TestMFAMethodOK struct {
}

// IsSuccess returns true when this test m f a method o k response has a 2xx status code
func (o *TestMFAMethodOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this test m f a method o k response has a 3xx status code
func (o *TestMFAMethodOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this test m f a method o k response has a 4xx status code
func (o *TestMFAMethodOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this test m f a method o k response has a 5xx status code
func (o *TestMFAMethodOK) IsServerError() bool {
	return false
}

// IsCode returns true when this test m f a method o k response a status code equal to that given
func (o *TestMFAMethodOK) IsCode(code int) bool {
	return code == 200
}

func (o *TestMFAMethodOK) Error() string {
	return fmt.Sprintf("[POST /mfa-methods/{mfaID}/test][%d] testMFAMethodOK ", 200)
}

func (o *TestMFAMethodOK) String() string {
	return fmt.Sprintf("[POST /mfa-methods/{mfaID}/test][%d] testMFAMethodOK ", 200)
}

func (o *TestMFAMethodOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewTestMFAMethodBadRequest creates a TestMFAMethodBadRequest with default headers values
func NewTestMFAMethodBadRequest() *TestMFAMethodBadRequest {
	return &TestMFAMethodBadRequest{}
}

/*
TestMFAMethodBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type TestMFAMethodBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this test m f a method bad request response has a 2xx status code
func (o *TestMFAMethodBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this test m f a method bad request response has a 3xx status code
func (o *TestMFAMethodBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this test m f a method bad request response has a 4xx status code
func (o *TestMFAMethodBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this test m f a method bad request response has a 5xx status code
func (o *TestMFAMethodBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this test m f a method bad request response a status code equal to that given
func (o *TestMFAMethodBadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *TestMFAMethodBadRequest) Error() string {
	return fmt.Sprintf("[POST /mfa-methods/{mfaID}/test][%d] testMFAMethodBadRequest  %+v", 400, o.Payload)
}

func (o *TestMFAMethodBadRequest) String() string {
	return fmt.Sprintf("[POST /mfa-methods/{mfaID}/test][%d] testMFAMethodBadRequest  %+v", 400, o.Payload)
}

func (o *TestMFAMethodBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *TestMFAMethodBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTestMFAMethodUnauthorized creates a TestMFAMethodUnauthorized with default headers values
func NewTestMFAMethodUnauthorized() *TestMFAMethodUnauthorized {
	return &TestMFAMethodUnauthorized{}
}

/*
TestMFAMethodUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type TestMFAMethodUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this test m f a method unauthorized response has a 2xx status code
func (o *TestMFAMethodUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this test m f a method unauthorized response has a 3xx status code
func (o *TestMFAMethodUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this test m f a method unauthorized response has a 4xx status code
func (o *TestMFAMethodUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this test m f a method unauthorized response has a 5xx status code
func (o *TestMFAMethodUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this test m f a method unauthorized response a status code equal to that given
func (o *TestMFAMethodUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *TestMFAMethodUnauthorized) Error() string {
	return fmt.Sprintf("[POST /mfa-methods/{mfaID}/test][%d] testMFAMethodUnauthorized  %+v", 401, o.Payload)
}

func (o *TestMFAMethodUnauthorized) String() string {
	return fmt.Sprintf("[POST /mfa-methods/{mfaID}/test][%d] testMFAMethodUnauthorized  %+v", 401, o.Payload)
}

func (o *TestMFAMethodUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *TestMFAMethodUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTestMFAMethodForbidden creates a TestMFAMethodForbidden with default headers values
func NewTestMFAMethodForbidden() *TestMFAMethodForbidden {
	return &TestMFAMethodForbidden{}
}

/*
TestMFAMethodForbidden describes a response with status code 403, with default header values.

HttpError
*/
type TestMFAMethodForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this test m f a method forbidden response has a 2xx status code
func (o *TestMFAMethodForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this test m f a method forbidden response has a 3xx status code
func (o *TestMFAMethodForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this test m f a method forbidden response has a 4xx status code
func (o *TestMFAMethodForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this test m f a method forbidden response has a 5xx status code
func (o *TestMFAMethodForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this test m f a method forbidden response a status code equal to that given
func (o *TestMFAMethodForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *TestMFAMethodForbidden) Error() string {
	return fmt.Sprintf("[POST /mfa-methods/{mfaID}/test][%d] testMFAMethodForbidden  %+v", 403, o.Payload)
}

func (o *TestMFAMethodForbidden) String() string {
	return fmt.Sprintf("[POST /mfa-methods/{mfaID}/test][%d] testMFAMethodForbidden  %+v", 403, o.Payload)
}

func (o *TestMFAMethodForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *TestMFAMethodForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTestMFAMethodNotFound creates a TestMFAMethodNotFound with default headers values
func NewTestMFAMethodNotFound() *TestMFAMethodNotFound {
	return &TestMFAMethodNotFound{}
}

/*
TestMFAMethodNotFound describes a response with status code 404, with default header values.

HttpError
*/
type TestMFAMethodNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this test m f a method not found response has a 2xx status code
func (o *TestMFAMethodNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this test m f a method not found response has a 3xx status code
func (o *TestMFAMethodNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this test m f a method not found response has a 4xx status code
func (o *TestMFAMethodNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this test m f a method not found response has a 5xx status code
func (o *TestMFAMethodNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this test m f a method not found response a status code equal to that given
func (o *TestMFAMethodNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *TestMFAMethodNotFound) Error() string {
	return fmt.Sprintf("[POST /mfa-methods/{mfaID}/test][%d] testMFAMethodNotFound  %+v", 404, o.Payload)
}

func (o *TestMFAMethodNotFound) String() string {
	return fmt.Sprintf("[POST /mfa-methods/{mfaID}/test][%d] testMFAMethodNotFound  %+v", 404, o.Payload)
}

func (o *TestMFAMethodNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *TestMFAMethodNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTestMFAMethodTooManyRequests creates a TestMFAMethodTooManyRequests with default headers values
func NewTestMFAMethodTooManyRequests() *TestMFAMethodTooManyRequests {
	return &TestMFAMethodTooManyRequests{}
}

/*
TestMFAMethodTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type TestMFAMethodTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this test m f a method too many requests response has a 2xx status code
func (o *TestMFAMethodTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this test m f a method too many requests response has a 3xx status code
func (o *TestMFAMethodTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this test m f a method too many requests response has a 4xx status code
func (o *TestMFAMethodTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this test m f a method too many requests response has a 5xx status code
func (o *TestMFAMethodTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this test m f a method too many requests response a status code equal to that given
func (o *TestMFAMethodTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *TestMFAMethodTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /mfa-methods/{mfaID}/test][%d] testMFAMethodTooManyRequests  %+v", 429, o.Payload)
}

func (o *TestMFAMethodTooManyRequests) String() string {
	return fmt.Sprintf("[POST /mfa-methods/{mfaID}/test][%d] testMFAMethodTooManyRequests  %+v", 429, o.Payload)
}

func (o *TestMFAMethodTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *TestMFAMethodTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
