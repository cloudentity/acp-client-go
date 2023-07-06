// Code generated by go-swagger; DO NOT EDIT.

package oauth2

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/oauth2/models"
)

// DynamicClientRegistrationGetClientReader is a Reader for the DynamicClientRegistrationGetClient structure.
type DynamicClientRegistrationGetClientReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DynamicClientRegistrationGetClientReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDynamicClientRegistrationGetClientOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDynamicClientRegistrationGetClientBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewDynamicClientRegistrationGetClientUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDynamicClientRegistrationGetClientForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDynamicClientRegistrationGetClientNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /oauth2/register/{cid}] dynamicClientRegistrationGetClient", response, response.Code())
	}
}

// NewDynamicClientRegistrationGetClientOK creates a DynamicClientRegistrationGetClientOK with default headers values
func NewDynamicClientRegistrationGetClientOK() *DynamicClientRegistrationGetClientOK {
	return &DynamicClientRegistrationGetClientOK{}
}

/*
DynamicClientRegistrationGetClientOK describes a response with status code 200, with default header values.

Dynamic client registration response
*/
type DynamicClientRegistrationGetClientOK struct {
	Payload *models.DynamicClientRegistrationResponse
}

// IsSuccess returns true when this dynamic client registration get client o k response has a 2xx status code
func (o *DynamicClientRegistrationGetClientOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this dynamic client registration get client o k response has a 3xx status code
func (o *DynamicClientRegistrationGetClientOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration get client o k response has a 4xx status code
func (o *DynamicClientRegistrationGetClientOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this dynamic client registration get client o k response has a 5xx status code
func (o *DynamicClientRegistrationGetClientOK) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration get client o k response a status code equal to that given
func (o *DynamicClientRegistrationGetClientOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the dynamic client registration get client o k response
func (o *DynamicClientRegistrationGetClientOK) Code() int {
	return 200
}

func (o *DynamicClientRegistrationGetClientOK) Error() string {
	return fmt.Sprintf("[GET /oauth2/register/{cid}][%d] dynamicClientRegistrationGetClientOK  %+v", 200, o.Payload)
}

func (o *DynamicClientRegistrationGetClientOK) String() string {
	return fmt.Sprintf("[GET /oauth2/register/{cid}][%d] dynamicClientRegistrationGetClientOK  %+v", 200, o.Payload)
}

func (o *DynamicClientRegistrationGetClientOK) GetPayload() *models.DynamicClientRegistrationResponse {
	return o.Payload
}

func (o *DynamicClientRegistrationGetClientOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.DynamicClientRegistrationResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationGetClientBadRequest creates a DynamicClientRegistrationGetClientBadRequest with default headers values
func NewDynamicClientRegistrationGetClientBadRequest() *DynamicClientRegistrationGetClientBadRequest {
	return &DynamicClientRegistrationGetClientBadRequest{}
}

/*
DynamicClientRegistrationGetClientBadRequest describes a response with status code 400, with default header values.

RFC6749 error
*/
type DynamicClientRegistrationGetClientBadRequest struct {
	Payload *models.RFC6749Error
}

// IsSuccess returns true when this dynamic client registration get client bad request response has a 2xx status code
func (o *DynamicClientRegistrationGetClientBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this dynamic client registration get client bad request response has a 3xx status code
func (o *DynamicClientRegistrationGetClientBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration get client bad request response has a 4xx status code
func (o *DynamicClientRegistrationGetClientBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this dynamic client registration get client bad request response has a 5xx status code
func (o *DynamicClientRegistrationGetClientBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration get client bad request response a status code equal to that given
func (o *DynamicClientRegistrationGetClientBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the dynamic client registration get client bad request response
func (o *DynamicClientRegistrationGetClientBadRequest) Code() int {
	return 400
}

func (o *DynamicClientRegistrationGetClientBadRequest) Error() string {
	return fmt.Sprintf("[GET /oauth2/register/{cid}][%d] dynamicClientRegistrationGetClientBadRequest  %+v", 400, o.Payload)
}

func (o *DynamicClientRegistrationGetClientBadRequest) String() string {
	return fmt.Sprintf("[GET /oauth2/register/{cid}][%d] dynamicClientRegistrationGetClientBadRequest  %+v", 400, o.Payload)
}

func (o *DynamicClientRegistrationGetClientBadRequest) GetPayload() *models.RFC6749Error {
	return o.Payload
}

func (o *DynamicClientRegistrationGetClientBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RFC6749Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationGetClientUnauthorized creates a DynamicClientRegistrationGetClientUnauthorized with default headers values
func NewDynamicClientRegistrationGetClientUnauthorized() *DynamicClientRegistrationGetClientUnauthorized {
	return &DynamicClientRegistrationGetClientUnauthorized{}
}

/*
DynamicClientRegistrationGetClientUnauthorized describes a response with status code 401, with default header values.

RFC6749 error
*/
type DynamicClientRegistrationGetClientUnauthorized struct {
	Payload *models.RFC6749Error
}

// IsSuccess returns true when this dynamic client registration get client unauthorized response has a 2xx status code
func (o *DynamicClientRegistrationGetClientUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this dynamic client registration get client unauthorized response has a 3xx status code
func (o *DynamicClientRegistrationGetClientUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration get client unauthorized response has a 4xx status code
func (o *DynamicClientRegistrationGetClientUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this dynamic client registration get client unauthorized response has a 5xx status code
func (o *DynamicClientRegistrationGetClientUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration get client unauthorized response a status code equal to that given
func (o *DynamicClientRegistrationGetClientUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the dynamic client registration get client unauthorized response
func (o *DynamicClientRegistrationGetClientUnauthorized) Code() int {
	return 401
}

func (o *DynamicClientRegistrationGetClientUnauthorized) Error() string {
	return fmt.Sprintf("[GET /oauth2/register/{cid}][%d] dynamicClientRegistrationGetClientUnauthorized  %+v", 401, o.Payload)
}

func (o *DynamicClientRegistrationGetClientUnauthorized) String() string {
	return fmt.Sprintf("[GET /oauth2/register/{cid}][%d] dynamicClientRegistrationGetClientUnauthorized  %+v", 401, o.Payload)
}

func (o *DynamicClientRegistrationGetClientUnauthorized) GetPayload() *models.RFC6749Error {
	return o.Payload
}

func (o *DynamicClientRegistrationGetClientUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RFC6749Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationGetClientForbidden creates a DynamicClientRegistrationGetClientForbidden with default headers values
func NewDynamicClientRegistrationGetClientForbidden() *DynamicClientRegistrationGetClientForbidden {
	return &DynamicClientRegistrationGetClientForbidden{}
}

/*
DynamicClientRegistrationGetClientForbidden describes a response with status code 403, with default header values.

RFC6749 error
*/
type DynamicClientRegistrationGetClientForbidden struct {
	Payload *models.RFC6749Error
}

// IsSuccess returns true when this dynamic client registration get client forbidden response has a 2xx status code
func (o *DynamicClientRegistrationGetClientForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this dynamic client registration get client forbidden response has a 3xx status code
func (o *DynamicClientRegistrationGetClientForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration get client forbidden response has a 4xx status code
func (o *DynamicClientRegistrationGetClientForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this dynamic client registration get client forbidden response has a 5xx status code
func (o *DynamicClientRegistrationGetClientForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration get client forbidden response a status code equal to that given
func (o *DynamicClientRegistrationGetClientForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the dynamic client registration get client forbidden response
func (o *DynamicClientRegistrationGetClientForbidden) Code() int {
	return 403
}

func (o *DynamicClientRegistrationGetClientForbidden) Error() string {
	return fmt.Sprintf("[GET /oauth2/register/{cid}][%d] dynamicClientRegistrationGetClientForbidden  %+v", 403, o.Payload)
}

func (o *DynamicClientRegistrationGetClientForbidden) String() string {
	return fmt.Sprintf("[GET /oauth2/register/{cid}][%d] dynamicClientRegistrationGetClientForbidden  %+v", 403, o.Payload)
}

func (o *DynamicClientRegistrationGetClientForbidden) GetPayload() *models.RFC6749Error {
	return o.Payload
}

func (o *DynamicClientRegistrationGetClientForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RFC6749Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationGetClientNotFound creates a DynamicClientRegistrationGetClientNotFound with default headers values
func NewDynamicClientRegistrationGetClientNotFound() *DynamicClientRegistrationGetClientNotFound {
	return &DynamicClientRegistrationGetClientNotFound{}
}

/*
DynamicClientRegistrationGetClientNotFound describes a response with status code 404, with default header values.

ErrorResponse
*/
type DynamicClientRegistrationGetClientNotFound struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this dynamic client registration get client not found response has a 2xx status code
func (o *DynamicClientRegistrationGetClientNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this dynamic client registration get client not found response has a 3xx status code
func (o *DynamicClientRegistrationGetClientNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration get client not found response has a 4xx status code
func (o *DynamicClientRegistrationGetClientNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this dynamic client registration get client not found response has a 5xx status code
func (o *DynamicClientRegistrationGetClientNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration get client not found response a status code equal to that given
func (o *DynamicClientRegistrationGetClientNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the dynamic client registration get client not found response
func (o *DynamicClientRegistrationGetClientNotFound) Code() int {
	return 404
}

func (o *DynamicClientRegistrationGetClientNotFound) Error() string {
	return fmt.Sprintf("[GET /oauth2/register/{cid}][%d] dynamicClientRegistrationGetClientNotFound  %+v", 404, o.Payload)
}

func (o *DynamicClientRegistrationGetClientNotFound) String() string {
	return fmt.Sprintf("[GET /oauth2/register/{cid}][%d] dynamicClientRegistrationGetClientNotFound  %+v", 404, o.Payload)
}

func (o *DynamicClientRegistrationGetClientNotFound) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *DynamicClientRegistrationGetClientNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
