// Code generated by go-swagger; DO NOT EDIT.

package apis

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

// TestAPIReader is a Reader for the TestAPI structure.
type TestAPIReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *TestAPIReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewTestAPIOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewTestAPIUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewTestAPIForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewTestAPINotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewTestAPIUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewTestAPITooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /apis/test] testAPI", response, response.Code())
	}
}

// NewTestAPIOK creates a TestAPIOK with default headers values
func NewTestAPIOK() *TestAPIOK {
	return &TestAPIOK{}
}

/*
TestAPIOK describes a response with status code 200, with default header values.

API test result
*/
type TestAPIOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.TestAPIResult
}

// IsSuccess returns true when this test Api o k response has a 2xx status code
func (o *TestAPIOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this test Api o k response has a 3xx status code
func (o *TestAPIOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this test Api o k response has a 4xx status code
func (o *TestAPIOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this test Api o k response has a 5xx status code
func (o *TestAPIOK) IsServerError() bool {
	return false
}

// IsCode returns true when this test Api o k response a status code equal to that given
func (o *TestAPIOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the test Api o k response
func (o *TestAPIOK) Code() int {
	return 200
}

func (o *TestAPIOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis/test][%d] testApiOK %s", 200, payload)
}

func (o *TestAPIOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis/test][%d] testApiOK %s", 200, payload)
}

func (o *TestAPIOK) GetPayload() *models.TestAPIResult {
	return o.Payload
}

func (o *TestAPIOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.TestAPIResult)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTestAPIUnauthorized creates a TestAPIUnauthorized with default headers values
func NewTestAPIUnauthorized() *TestAPIUnauthorized {
	return &TestAPIUnauthorized{}
}

/*
TestAPIUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type TestAPIUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this test Api unauthorized response has a 2xx status code
func (o *TestAPIUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this test Api unauthorized response has a 3xx status code
func (o *TestAPIUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this test Api unauthorized response has a 4xx status code
func (o *TestAPIUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this test Api unauthorized response has a 5xx status code
func (o *TestAPIUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this test Api unauthorized response a status code equal to that given
func (o *TestAPIUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the test Api unauthorized response
func (o *TestAPIUnauthorized) Code() int {
	return 401
}

func (o *TestAPIUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis/test][%d] testApiUnauthorized %s", 401, payload)
}

func (o *TestAPIUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis/test][%d] testApiUnauthorized %s", 401, payload)
}

func (o *TestAPIUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *TestAPIUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTestAPIForbidden creates a TestAPIForbidden with default headers values
func NewTestAPIForbidden() *TestAPIForbidden {
	return &TestAPIForbidden{}
}

/*
TestAPIForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type TestAPIForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this test Api forbidden response has a 2xx status code
func (o *TestAPIForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this test Api forbidden response has a 3xx status code
func (o *TestAPIForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this test Api forbidden response has a 4xx status code
func (o *TestAPIForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this test Api forbidden response has a 5xx status code
func (o *TestAPIForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this test Api forbidden response a status code equal to that given
func (o *TestAPIForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the test Api forbidden response
func (o *TestAPIForbidden) Code() int {
	return 403
}

func (o *TestAPIForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis/test][%d] testApiForbidden %s", 403, payload)
}

func (o *TestAPIForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis/test][%d] testApiForbidden %s", 403, payload)
}

func (o *TestAPIForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *TestAPIForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTestAPINotFound creates a TestAPINotFound with default headers values
func NewTestAPINotFound() *TestAPINotFound {
	return &TestAPINotFound{}
}

/*
TestAPINotFound describes a response with status code 404, with default header values.

Not found
*/
type TestAPINotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this test Api not found response has a 2xx status code
func (o *TestAPINotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this test Api not found response has a 3xx status code
func (o *TestAPINotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this test Api not found response has a 4xx status code
func (o *TestAPINotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this test Api not found response has a 5xx status code
func (o *TestAPINotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this test Api not found response a status code equal to that given
func (o *TestAPINotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the test Api not found response
func (o *TestAPINotFound) Code() int {
	return 404
}

func (o *TestAPINotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis/test][%d] testApiNotFound %s", 404, payload)
}

func (o *TestAPINotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis/test][%d] testApiNotFound %s", 404, payload)
}

func (o *TestAPINotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *TestAPINotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTestAPIUnprocessableEntity creates a TestAPIUnprocessableEntity with default headers values
func NewTestAPIUnprocessableEntity() *TestAPIUnprocessableEntity {
	return &TestAPIUnprocessableEntity{}
}

/*
TestAPIUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type TestAPIUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this test Api unprocessable entity response has a 2xx status code
func (o *TestAPIUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this test Api unprocessable entity response has a 3xx status code
func (o *TestAPIUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this test Api unprocessable entity response has a 4xx status code
func (o *TestAPIUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this test Api unprocessable entity response has a 5xx status code
func (o *TestAPIUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this test Api unprocessable entity response a status code equal to that given
func (o *TestAPIUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the test Api unprocessable entity response
func (o *TestAPIUnprocessableEntity) Code() int {
	return 422
}

func (o *TestAPIUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis/test][%d] testApiUnprocessableEntity %s", 422, payload)
}

func (o *TestAPIUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis/test][%d] testApiUnprocessableEntity %s", 422, payload)
}

func (o *TestAPIUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *TestAPIUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTestAPITooManyRequests creates a TestAPITooManyRequests with default headers values
func NewTestAPITooManyRequests() *TestAPITooManyRequests {
	return &TestAPITooManyRequests{}
}

/*
TestAPITooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type TestAPITooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this test Api too many requests response has a 2xx status code
func (o *TestAPITooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this test Api too many requests response has a 3xx status code
func (o *TestAPITooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this test Api too many requests response has a 4xx status code
func (o *TestAPITooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this test Api too many requests response has a 5xx status code
func (o *TestAPITooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this test Api too many requests response a status code equal to that given
func (o *TestAPITooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the test Api too many requests response
func (o *TestAPITooManyRequests) Code() int {
	return 429
}

func (o *TestAPITooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis/test][%d] testApiTooManyRequests %s", 429, payload)
}

func (o *TestAPITooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis/test][%d] testApiTooManyRequests %s", 429, payload)
}

func (o *TestAPITooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *TestAPITooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
