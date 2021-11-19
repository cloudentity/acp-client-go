// Code generated by go-swagger; DO NOT EDIT.

package mfa_methods

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/acp/models"
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

/* TestMFAMethodOK describes a response with status code 200, with default header values.

MFA OTP message sent
*/
type TestMFAMethodOK struct {
}

func (o *TestMFAMethodOK) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/mfa-methods/{mfaID}/test][%d] testMFAMethodOK ", 200)
}

func (o *TestMFAMethodOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewTestMFAMethodBadRequest creates a TestMFAMethodBadRequest with default headers values
func NewTestMFAMethodBadRequest() *TestMFAMethodBadRequest {
	return &TestMFAMethodBadRequest{}
}

/* TestMFAMethodBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type TestMFAMethodBadRequest struct {
	Payload *models.Error
}

func (o *TestMFAMethodBadRequest) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/mfa-methods/{mfaID}/test][%d] testMFAMethodBadRequest  %+v", 400, o.Payload)
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

/* TestMFAMethodUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type TestMFAMethodUnauthorized struct {
	Payload *models.Error
}

func (o *TestMFAMethodUnauthorized) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/mfa-methods/{mfaID}/test][%d] testMFAMethodUnauthorized  %+v", 401, o.Payload)
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

/* TestMFAMethodForbidden describes a response with status code 403, with default header values.

HttpError
*/
type TestMFAMethodForbidden struct {
	Payload *models.Error
}

func (o *TestMFAMethodForbidden) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/mfa-methods/{mfaID}/test][%d] testMFAMethodForbidden  %+v", 403, o.Payload)
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

/* TestMFAMethodNotFound describes a response with status code 404, with default header values.

HttpError
*/
type TestMFAMethodNotFound struct {
	Payload *models.Error
}

func (o *TestMFAMethodNotFound) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/mfa-methods/{mfaID}/test][%d] testMFAMethodNotFound  %+v", 404, o.Payload)
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

/* TestMFAMethodTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type TestMFAMethodTooManyRequests struct {
	Payload *models.Error
}

func (o *TestMFAMethodTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/mfa-methods/{mfaID}/test][%d] testMFAMethodTooManyRequests  %+v", 429, o.Payload)
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