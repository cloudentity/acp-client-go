// Code generated by go-swagger; DO NOT EDIT.

package d_c_r

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/cdr/models"
)

// DynamicClientRegistrationReader is a Reader for the DynamicClientRegistration structure.
type DynamicClientRegistrationReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DynamicClientRegistrationReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewDynamicClientRegistrationCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDynamicClientRegistrationBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewDynamicClientRegistrationUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDynamicClientRegistrationForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDynamicClientRegistrationNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewDynamicClientRegistrationCreated creates a DynamicClientRegistrationCreated with default headers values
func NewDynamicClientRegistrationCreated() *DynamicClientRegistrationCreated {
	return &DynamicClientRegistrationCreated{}
}

/*
DynamicClientRegistrationCreated describes a response with status code 201, with default header values.

Dynamic client registration response
*/
type DynamicClientRegistrationCreated struct {
	Payload *models.CDRDynamicClientRegistrationResponse
}

// IsSuccess returns true when this dynamic client registration created response has a 2xx status code
func (o *DynamicClientRegistrationCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this dynamic client registration created response has a 3xx status code
func (o *DynamicClientRegistrationCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration created response has a 4xx status code
func (o *DynamicClientRegistrationCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this dynamic client registration created response has a 5xx status code
func (o *DynamicClientRegistrationCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration created response a status code equal to that given
func (o *DynamicClientRegistrationCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the dynamic client registration created response
func (o *DynamicClientRegistrationCreated) Code() int {
	return 201
}

func (o *DynamicClientRegistrationCreated) Error() string {
	return fmt.Sprintf("[POST /oauth2/register][%d] dynamicClientRegistrationCreated  %+v", 201, o.Payload)
}

func (o *DynamicClientRegistrationCreated) String() string {
	return fmt.Sprintf("[POST /oauth2/register][%d] dynamicClientRegistrationCreated  %+v", 201, o.Payload)
}

func (o *DynamicClientRegistrationCreated) GetPayload() *models.CDRDynamicClientRegistrationResponse {
	return o.Payload
}

func (o *DynamicClientRegistrationCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.CDRDynamicClientRegistrationResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationBadRequest creates a DynamicClientRegistrationBadRequest with default headers values
func NewDynamicClientRegistrationBadRequest() *DynamicClientRegistrationBadRequest {
	return &DynamicClientRegistrationBadRequest{}
}

/*
DynamicClientRegistrationBadRequest describes a response with status code 400, with default header values.

RFC6749 error
*/
type DynamicClientRegistrationBadRequest struct {
	Payload *models.RFC6749Error
}

// IsSuccess returns true when this dynamic client registration bad request response has a 2xx status code
func (o *DynamicClientRegistrationBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this dynamic client registration bad request response has a 3xx status code
func (o *DynamicClientRegistrationBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration bad request response has a 4xx status code
func (o *DynamicClientRegistrationBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this dynamic client registration bad request response has a 5xx status code
func (o *DynamicClientRegistrationBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration bad request response a status code equal to that given
func (o *DynamicClientRegistrationBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the dynamic client registration bad request response
func (o *DynamicClientRegistrationBadRequest) Code() int {
	return 400
}

func (o *DynamicClientRegistrationBadRequest) Error() string {
	return fmt.Sprintf("[POST /oauth2/register][%d] dynamicClientRegistrationBadRequest  %+v", 400, o.Payload)
}

func (o *DynamicClientRegistrationBadRequest) String() string {
	return fmt.Sprintf("[POST /oauth2/register][%d] dynamicClientRegistrationBadRequest  %+v", 400, o.Payload)
}

func (o *DynamicClientRegistrationBadRequest) GetPayload() *models.RFC6749Error {
	return o.Payload
}

func (o *DynamicClientRegistrationBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RFC6749Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationUnauthorized creates a DynamicClientRegistrationUnauthorized with default headers values
func NewDynamicClientRegistrationUnauthorized() *DynamicClientRegistrationUnauthorized {
	return &DynamicClientRegistrationUnauthorized{}
}

/*
DynamicClientRegistrationUnauthorized describes a response with status code 401, with default header values.

RFC6749 error
*/
type DynamicClientRegistrationUnauthorized struct {
	Payload *models.RFC6749Error
}

// IsSuccess returns true when this dynamic client registration unauthorized response has a 2xx status code
func (o *DynamicClientRegistrationUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this dynamic client registration unauthorized response has a 3xx status code
func (o *DynamicClientRegistrationUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration unauthorized response has a 4xx status code
func (o *DynamicClientRegistrationUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this dynamic client registration unauthorized response has a 5xx status code
func (o *DynamicClientRegistrationUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration unauthorized response a status code equal to that given
func (o *DynamicClientRegistrationUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the dynamic client registration unauthorized response
func (o *DynamicClientRegistrationUnauthorized) Code() int {
	return 401
}

func (o *DynamicClientRegistrationUnauthorized) Error() string {
	return fmt.Sprintf("[POST /oauth2/register][%d] dynamicClientRegistrationUnauthorized  %+v", 401, o.Payload)
}

func (o *DynamicClientRegistrationUnauthorized) String() string {
	return fmt.Sprintf("[POST /oauth2/register][%d] dynamicClientRegistrationUnauthorized  %+v", 401, o.Payload)
}

func (o *DynamicClientRegistrationUnauthorized) GetPayload() *models.RFC6749Error {
	return o.Payload
}

func (o *DynamicClientRegistrationUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RFC6749Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationForbidden creates a DynamicClientRegistrationForbidden with default headers values
func NewDynamicClientRegistrationForbidden() *DynamicClientRegistrationForbidden {
	return &DynamicClientRegistrationForbidden{}
}

/*
DynamicClientRegistrationForbidden describes a response with status code 403, with default header values.

RFC6749 error
*/
type DynamicClientRegistrationForbidden struct {
	Payload *models.RFC6749Error
}

// IsSuccess returns true when this dynamic client registration forbidden response has a 2xx status code
func (o *DynamicClientRegistrationForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this dynamic client registration forbidden response has a 3xx status code
func (o *DynamicClientRegistrationForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration forbidden response has a 4xx status code
func (o *DynamicClientRegistrationForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this dynamic client registration forbidden response has a 5xx status code
func (o *DynamicClientRegistrationForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration forbidden response a status code equal to that given
func (o *DynamicClientRegistrationForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the dynamic client registration forbidden response
func (o *DynamicClientRegistrationForbidden) Code() int {
	return 403
}

func (o *DynamicClientRegistrationForbidden) Error() string {
	return fmt.Sprintf("[POST /oauth2/register][%d] dynamicClientRegistrationForbidden  %+v", 403, o.Payload)
}

func (o *DynamicClientRegistrationForbidden) String() string {
	return fmt.Sprintf("[POST /oauth2/register][%d] dynamicClientRegistrationForbidden  %+v", 403, o.Payload)
}

func (o *DynamicClientRegistrationForbidden) GetPayload() *models.RFC6749Error {
	return o.Payload
}

func (o *DynamicClientRegistrationForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RFC6749Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationNotFound creates a DynamicClientRegistrationNotFound with default headers values
func NewDynamicClientRegistrationNotFound() *DynamicClientRegistrationNotFound {
	return &DynamicClientRegistrationNotFound{}
}

/*
DynamicClientRegistrationNotFound describes a response with status code 404, with default header values.

ErrorResponse
*/
type DynamicClientRegistrationNotFound struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this dynamic client registration not found response has a 2xx status code
func (o *DynamicClientRegistrationNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this dynamic client registration not found response has a 3xx status code
func (o *DynamicClientRegistrationNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration not found response has a 4xx status code
func (o *DynamicClientRegistrationNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this dynamic client registration not found response has a 5xx status code
func (o *DynamicClientRegistrationNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration not found response a status code equal to that given
func (o *DynamicClientRegistrationNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the dynamic client registration not found response
func (o *DynamicClientRegistrationNotFound) Code() int {
	return 404
}

func (o *DynamicClientRegistrationNotFound) Error() string {
	return fmt.Sprintf("[POST /oauth2/register][%d] dynamicClientRegistrationNotFound  %+v", 404, o.Payload)
}

func (o *DynamicClientRegistrationNotFound) String() string {
	return fmt.Sprintf("[POST /oauth2/register][%d] dynamicClientRegistrationNotFound  %+v", 404, o.Payload)
}

func (o *DynamicClientRegistrationNotFound) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *DynamicClientRegistrationNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}