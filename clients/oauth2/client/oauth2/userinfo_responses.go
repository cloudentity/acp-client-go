// Code generated by go-swagger; DO NOT EDIT.

package oauth2

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/oauth2/models"
)

// UserinfoReader is a Reader for the Userinfo structure.
type UserinfoReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UserinfoReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUserinfoOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewUserinfoUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUserinfoNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUserinfoTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /userinfo] userinfo", response, response.Code())
	}
}

// NewUserinfoOK creates a UserinfoOK with default headers values
func NewUserinfoOK() *UserinfoOK {
	return &UserinfoOK{}
}

/*
UserinfoOK describes a response with status code 200, with default header values.

Userinfo
*/
type UserinfoOK struct {
	Payload *models.UserinfoResponse
}

// IsSuccess returns true when this userinfo o k response has a 2xx status code
func (o *UserinfoOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this userinfo o k response has a 3xx status code
func (o *UserinfoOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this userinfo o k response has a 4xx status code
func (o *UserinfoOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this userinfo o k response has a 5xx status code
func (o *UserinfoOK) IsServerError() bool {
	return false
}

// IsCode returns true when this userinfo o k response a status code equal to that given
func (o *UserinfoOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the userinfo o k response
func (o *UserinfoOK) Code() int {
	return 200
}

func (o *UserinfoOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /userinfo][%d] userinfoOK %s", 200, payload)
}

func (o *UserinfoOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /userinfo][%d] userinfoOK %s", 200, payload)
}

func (o *UserinfoOK) GetPayload() *models.UserinfoResponse {
	return o.Payload
}

func (o *UserinfoOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.UserinfoResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUserinfoUnauthorized creates a UserinfoUnauthorized with default headers values
func NewUserinfoUnauthorized() *UserinfoUnauthorized {
	return &UserinfoUnauthorized{}
}

/*
UserinfoUnauthorized describes a response with status code 401, with default header values.

ErrorResponse
*/
type UserinfoUnauthorized struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this userinfo unauthorized response has a 2xx status code
func (o *UserinfoUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this userinfo unauthorized response has a 3xx status code
func (o *UserinfoUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this userinfo unauthorized response has a 4xx status code
func (o *UserinfoUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this userinfo unauthorized response has a 5xx status code
func (o *UserinfoUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this userinfo unauthorized response a status code equal to that given
func (o *UserinfoUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the userinfo unauthorized response
func (o *UserinfoUnauthorized) Code() int {
	return 401
}

func (o *UserinfoUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /userinfo][%d] userinfoUnauthorized %s", 401, payload)
}

func (o *UserinfoUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /userinfo][%d] userinfoUnauthorized %s", 401, payload)
}

func (o *UserinfoUnauthorized) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *UserinfoUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUserinfoNotFound creates a UserinfoNotFound with default headers values
func NewUserinfoNotFound() *UserinfoNotFound {
	return &UserinfoNotFound{}
}

/*
UserinfoNotFound describes a response with status code 404, with default header values.

ErrorResponse
*/
type UserinfoNotFound struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this userinfo not found response has a 2xx status code
func (o *UserinfoNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this userinfo not found response has a 3xx status code
func (o *UserinfoNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this userinfo not found response has a 4xx status code
func (o *UserinfoNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this userinfo not found response has a 5xx status code
func (o *UserinfoNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this userinfo not found response a status code equal to that given
func (o *UserinfoNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the userinfo not found response
func (o *UserinfoNotFound) Code() int {
	return 404
}

func (o *UserinfoNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /userinfo][%d] userinfoNotFound %s", 404, payload)
}

func (o *UserinfoNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /userinfo][%d] userinfoNotFound %s", 404, payload)
}

func (o *UserinfoNotFound) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *UserinfoNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUserinfoTooManyRequests creates a UserinfoTooManyRequests with default headers values
func NewUserinfoTooManyRequests() *UserinfoTooManyRequests {
	return &UserinfoTooManyRequests{}
}

/*
UserinfoTooManyRequests describes a response with status code 429, with default header values.

ErrorResponse
*/
type UserinfoTooManyRequests struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this userinfo too many requests response has a 2xx status code
func (o *UserinfoTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this userinfo too many requests response has a 3xx status code
func (o *UserinfoTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this userinfo too many requests response has a 4xx status code
func (o *UserinfoTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this userinfo too many requests response has a 5xx status code
func (o *UserinfoTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this userinfo too many requests response a status code equal to that given
func (o *UserinfoTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the userinfo too many requests response
func (o *UserinfoTooManyRequests) Code() int {
	return 429
}

func (o *UserinfoTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /userinfo][%d] userinfoTooManyRequests %s", 429, payload)
}

func (o *UserinfoTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /userinfo][%d] userinfoTooManyRequests %s", 429, payload)
}

func (o *UserinfoTooManyRequests) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *UserinfoTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
