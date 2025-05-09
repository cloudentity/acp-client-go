// Code generated by go-swagger; DO NOT EDIT.

package policies

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

// TestPolicyReader is a Reader for the TestPolicy structure.
type TestPolicyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *TestPolicyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewTestPolicyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewTestPolicyBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewTestPolicyUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewTestPolicyForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewTestPolicyNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewTestPolicyConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewTestPolicyUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewTestPolicyTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /policies/test] testPolicy", response, response.Code())
	}
}

// NewTestPolicyOK creates a TestPolicyOK with default headers values
func NewTestPolicyOK() *TestPolicyOK {
	return &TestPolicyOK{}
}

/*
TestPolicyOK describes a response with status code 200, with default header values.

Test policy result
*/
type TestPolicyOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.TestPolicyResponse
}

// IsSuccess returns true when this test policy o k response has a 2xx status code
func (o *TestPolicyOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this test policy o k response has a 3xx status code
func (o *TestPolicyOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this test policy o k response has a 4xx status code
func (o *TestPolicyOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this test policy o k response has a 5xx status code
func (o *TestPolicyOK) IsServerError() bool {
	return false
}

// IsCode returns true when this test policy o k response a status code equal to that given
func (o *TestPolicyOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the test policy o k response
func (o *TestPolicyOK) Code() int {
	return 200
}

func (o *TestPolicyOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /policies/test][%d] testPolicyOK %s", 200, payload)
}

func (o *TestPolicyOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /policies/test][%d] testPolicyOK %s", 200, payload)
}

func (o *TestPolicyOK) GetPayload() *models.TestPolicyResponse {
	return o.Payload
}

func (o *TestPolicyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.TestPolicyResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTestPolicyBadRequest creates a TestPolicyBadRequest with default headers values
func NewTestPolicyBadRequest() *TestPolicyBadRequest {
	return &TestPolicyBadRequest{}
}

/*
TestPolicyBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type TestPolicyBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this test policy bad request response has a 2xx status code
func (o *TestPolicyBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this test policy bad request response has a 3xx status code
func (o *TestPolicyBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this test policy bad request response has a 4xx status code
func (o *TestPolicyBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this test policy bad request response has a 5xx status code
func (o *TestPolicyBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this test policy bad request response a status code equal to that given
func (o *TestPolicyBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the test policy bad request response
func (o *TestPolicyBadRequest) Code() int {
	return 400
}

func (o *TestPolicyBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /policies/test][%d] testPolicyBadRequest %s", 400, payload)
}

func (o *TestPolicyBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /policies/test][%d] testPolicyBadRequest %s", 400, payload)
}

func (o *TestPolicyBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *TestPolicyBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTestPolicyUnauthorized creates a TestPolicyUnauthorized with default headers values
func NewTestPolicyUnauthorized() *TestPolicyUnauthorized {
	return &TestPolicyUnauthorized{}
}

/*
TestPolicyUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type TestPolicyUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this test policy unauthorized response has a 2xx status code
func (o *TestPolicyUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this test policy unauthorized response has a 3xx status code
func (o *TestPolicyUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this test policy unauthorized response has a 4xx status code
func (o *TestPolicyUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this test policy unauthorized response has a 5xx status code
func (o *TestPolicyUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this test policy unauthorized response a status code equal to that given
func (o *TestPolicyUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the test policy unauthorized response
func (o *TestPolicyUnauthorized) Code() int {
	return 401
}

func (o *TestPolicyUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /policies/test][%d] testPolicyUnauthorized %s", 401, payload)
}

func (o *TestPolicyUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /policies/test][%d] testPolicyUnauthorized %s", 401, payload)
}

func (o *TestPolicyUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *TestPolicyUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTestPolicyForbidden creates a TestPolicyForbidden with default headers values
func NewTestPolicyForbidden() *TestPolicyForbidden {
	return &TestPolicyForbidden{}
}

/*
TestPolicyForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type TestPolicyForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this test policy forbidden response has a 2xx status code
func (o *TestPolicyForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this test policy forbidden response has a 3xx status code
func (o *TestPolicyForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this test policy forbidden response has a 4xx status code
func (o *TestPolicyForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this test policy forbidden response has a 5xx status code
func (o *TestPolicyForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this test policy forbidden response a status code equal to that given
func (o *TestPolicyForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the test policy forbidden response
func (o *TestPolicyForbidden) Code() int {
	return 403
}

func (o *TestPolicyForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /policies/test][%d] testPolicyForbidden %s", 403, payload)
}

func (o *TestPolicyForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /policies/test][%d] testPolicyForbidden %s", 403, payload)
}

func (o *TestPolicyForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *TestPolicyForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTestPolicyNotFound creates a TestPolicyNotFound with default headers values
func NewTestPolicyNotFound() *TestPolicyNotFound {
	return &TestPolicyNotFound{}
}

/*
TestPolicyNotFound describes a response with status code 404, with default header values.

Not found
*/
type TestPolicyNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this test policy not found response has a 2xx status code
func (o *TestPolicyNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this test policy not found response has a 3xx status code
func (o *TestPolicyNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this test policy not found response has a 4xx status code
func (o *TestPolicyNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this test policy not found response has a 5xx status code
func (o *TestPolicyNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this test policy not found response a status code equal to that given
func (o *TestPolicyNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the test policy not found response
func (o *TestPolicyNotFound) Code() int {
	return 404
}

func (o *TestPolicyNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /policies/test][%d] testPolicyNotFound %s", 404, payload)
}

func (o *TestPolicyNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /policies/test][%d] testPolicyNotFound %s", 404, payload)
}

func (o *TestPolicyNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *TestPolicyNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTestPolicyConflict creates a TestPolicyConflict with default headers values
func NewTestPolicyConflict() *TestPolicyConflict {
	return &TestPolicyConflict{}
}

/*
TestPolicyConflict describes a response with status code 409, with default header values.

Conflict
*/
type TestPolicyConflict struct {
	Payload *models.Error
}

// IsSuccess returns true when this test policy conflict response has a 2xx status code
func (o *TestPolicyConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this test policy conflict response has a 3xx status code
func (o *TestPolicyConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this test policy conflict response has a 4xx status code
func (o *TestPolicyConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this test policy conflict response has a 5xx status code
func (o *TestPolicyConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this test policy conflict response a status code equal to that given
func (o *TestPolicyConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the test policy conflict response
func (o *TestPolicyConflict) Code() int {
	return 409
}

func (o *TestPolicyConflict) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /policies/test][%d] testPolicyConflict %s", 409, payload)
}

func (o *TestPolicyConflict) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /policies/test][%d] testPolicyConflict %s", 409, payload)
}

func (o *TestPolicyConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *TestPolicyConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTestPolicyUnprocessableEntity creates a TestPolicyUnprocessableEntity with default headers values
func NewTestPolicyUnprocessableEntity() *TestPolicyUnprocessableEntity {
	return &TestPolicyUnprocessableEntity{}
}

/*
TestPolicyUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type TestPolicyUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this test policy unprocessable entity response has a 2xx status code
func (o *TestPolicyUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this test policy unprocessable entity response has a 3xx status code
func (o *TestPolicyUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this test policy unprocessable entity response has a 4xx status code
func (o *TestPolicyUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this test policy unprocessable entity response has a 5xx status code
func (o *TestPolicyUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this test policy unprocessable entity response a status code equal to that given
func (o *TestPolicyUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the test policy unprocessable entity response
func (o *TestPolicyUnprocessableEntity) Code() int {
	return 422
}

func (o *TestPolicyUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /policies/test][%d] testPolicyUnprocessableEntity %s", 422, payload)
}

func (o *TestPolicyUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /policies/test][%d] testPolicyUnprocessableEntity %s", 422, payload)
}

func (o *TestPolicyUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *TestPolicyUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTestPolicyTooManyRequests creates a TestPolicyTooManyRequests with default headers values
func NewTestPolicyTooManyRequests() *TestPolicyTooManyRequests {
	return &TestPolicyTooManyRequests{}
}

/*
TestPolicyTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type TestPolicyTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this test policy too many requests response has a 2xx status code
func (o *TestPolicyTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this test policy too many requests response has a 3xx status code
func (o *TestPolicyTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this test policy too many requests response has a 4xx status code
func (o *TestPolicyTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this test policy too many requests response has a 5xx status code
func (o *TestPolicyTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this test policy too many requests response a status code equal to that given
func (o *TestPolicyTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the test policy too many requests response
func (o *TestPolicyTooManyRequests) Code() int {
	return 429
}

func (o *TestPolicyTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /policies/test][%d] testPolicyTooManyRequests %s", 429, payload)
}

func (o *TestPolicyTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /policies/test][%d] testPolicyTooManyRequests %s", 429, payload)
}

func (o *TestPolicyTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *TestPolicyTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
