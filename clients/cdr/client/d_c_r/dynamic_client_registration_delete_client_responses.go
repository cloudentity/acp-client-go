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

// DynamicClientRegistrationDeleteClientReader is a Reader for the DynamicClientRegistrationDeleteClient structure.
type DynamicClientRegistrationDeleteClientReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DynamicClientRegistrationDeleteClientReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewDynamicClientRegistrationDeleteClientNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDynamicClientRegistrationDeleteClientBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewDynamicClientRegistrationDeleteClientUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDynamicClientRegistrationDeleteClientForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDynamicClientRegistrationDeleteClientNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /oauth2/register/{cid}] dynamicClientRegistrationDeleteClient", response, response.Code())
	}
}

// NewDynamicClientRegistrationDeleteClientNoContent creates a DynamicClientRegistrationDeleteClientNoContent with default headers values
func NewDynamicClientRegistrationDeleteClientNoContent() *DynamicClientRegistrationDeleteClientNoContent {
	return &DynamicClientRegistrationDeleteClientNoContent{}
}

/*
DynamicClientRegistrationDeleteClientNoContent describes a response with status code 204, with default header values.

	Client has been deleted
*/
type DynamicClientRegistrationDeleteClientNoContent struct {
}

// IsSuccess returns true when this dynamic client registration delete client no content response has a 2xx status code
func (o *DynamicClientRegistrationDeleteClientNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this dynamic client registration delete client no content response has a 3xx status code
func (o *DynamicClientRegistrationDeleteClientNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration delete client no content response has a 4xx status code
func (o *DynamicClientRegistrationDeleteClientNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this dynamic client registration delete client no content response has a 5xx status code
func (o *DynamicClientRegistrationDeleteClientNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration delete client no content response a status code equal to that given
func (o *DynamicClientRegistrationDeleteClientNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the dynamic client registration delete client no content response
func (o *DynamicClientRegistrationDeleteClientNoContent) Code() int {
	return 204
}

func (o *DynamicClientRegistrationDeleteClientNoContent) Error() string {
	return fmt.Sprintf("[DELETE /oauth2/register/{cid}][%d] dynamicClientRegistrationDeleteClientNoContent ", 204)
}

func (o *DynamicClientRegistrationDeleteClientNoContent) String() string {
	return fmt.Sprintf("[DELETE /oauth2/register/{cid}][%d] dynamicClientRegistrationDeleteClientNoContent ", 204)
}

func (o *DynamicClientRegistrationDeleteClientNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDynamicClientRegistrationDeleteClientBadRequest creates a DynamicClientRegistrationDeleteClientBadRequest with default headers values
func NewDynamicClientRegistrationDeleteClientBadRequest() *DynamicClientRegistrationDeleteClientBadRequest {
	return &DynamicClientRegistrationDeleteClientBadRequest{}
}

/*
DynamicClientRegistrationDeleteClientBadRequest describes a response with status code 400, with default header values.

RFC6749 error
*/
type DynamicClientRegistrationDeleteClientBadRequest struct {
	Payload *models.RFC6749Error
}

// IsSuccess returns true when this dynamic client registration delete client bad request response has a 2xx status code
func (o *DynamicClientRegistrationDeleteClientBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this dynamic client registration delete client bad request response has a 3xx status code
func (o *DynamicClientRegistrationDeleteClientBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration delete client bad request response has a 4xx status code
func (o *DynamicClientRegistrationDeleteClientBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this dynamic client registration delete client bad request response has a 5xx status code
func (o *DynamicClientRegistrationDeleteClientBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration delete client bad request response a status code equal to that given
func (o *DynamicClientRegistrationDeleteClientBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the dynamic client registration delete client bad request response
func (o *DynamicClientRegistrationDeleteClientBadRequest) Code() int {
	return 400
}

func (o *DynamicClientRegistrationDeleteClientBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /oauth2/register/{cid}][%d] dynamicClientRegistrationDeleteClientBadRequest  %+v", 400, o.Payload)
}

func (o *DynamicClientRegistrationDeleteClientBadRequest) String() string {
	return fmt.Sprintf("[DELETE /oauth2/register/{cid}][%d] dynamicClientRegistrationDeleteClientBadRequest  %+v", 400, o.Payload)
}

func (o *DynamicClientRegistrationDeleteClientBadRequest) GetPayload() *models.RFC6749Error {
	return o.Payload
}

func (o *DynamicClientRegistrationDeleteClientBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RFC6749Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationDeleteClientUnauthorized creates a DynamicClientRegistrationDeleteClientUnauthorized with default headers values
func NewDynamicClientRegistrationDeleteClientUnauthorized() *DynamicClientRegistrationDeleteClientUnauthorized {
	return &DynamicClientRegistrationDeleteClientUnauthorized{}
}

/*
DynamicClientRegistrationDeleteClientUnauthorized describes a response with status code 401, with default header values.

RFC6749 error
*/
type DynamicClientRegistrationDeleteClientUnauthorized struct {
	Payload *models.RFC6749Error
}

// IsSuccess returns true when this dynamic client registration delete client unauthorized response has a 2xx status code
func (o *DynamicClientRegistrationDeleteClientUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this dynamic client registration delete client unauthorized response has a 3xx status code
func (o *DynamicClientRegistrationDeleteClientUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration delete client unauthorized response has a 4xx status code
func (o *DynamicClientRegistrationDeleteClientUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this dynamic client registration delete client unauthorized response has a 5xx status code
func (o *DynamicClientRegistrationDeleteClientUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration delete client unauthorized response a status code equal to that given
func (o *DynamicClientRegistrationDeleteClientUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the dynamic client registration delete client unauthorized response
func (o *DynamicClientRegistrationDeleteClientUnauthorized) Code() int {
	return 401
}

func (o *DynamicClientRegistrationDeleteClientUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /oauth2/register/{cid}][%d] dynamicClientRegistrationDeleteClientUnauthorized  %+v", 401, o.Payload)
}

func (o *DynamicClientRegistrationDeleteClientUnauthorized) String() string {
	return fmt.Sprintf("[DELETE /oauth2/register/{cid}][%d] dynamicClientRegistrationDeleteClientUnauthorized  %+v", 401, o.Payload)
}

func (o *DynamicClientRegistrationDeleteClientUnauthorized) GetPayload() *models.RFC6749Error {
	return o.Payload
}

func (o *DynamicClientRegistrationDeleteClientUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RFC6749Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationDeleteClientForbidden creates a DynamicClientRegistrationDeleteClientForbidden with default headers values
func NewDynamicClientRegistrationDeleteClientForbidden() *DynamicClientRegistrationDeleteClientForbidden {
	return &DynamicClientRegistrationDeleteClientForbidden{}
}

/*
DynamicClientRegistrationDeleteClientForbidden describes a response with status code 403, with default header values.

RFC6749 error
*/
type DynamicClientRegistrationDeleteClientForbidden struct {
	Payload *models.RFC6749Error
}

// IsSuccess returns true when this dynamic client registration delete client forbidden response has a 2xx status code
func (o *DynamicClientRegistrationDeleteClientForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this dynamic client registration delete client forbidden response has a 3xx status code
func (o *DynamicClientRegistrationDeleteClientForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration delete client forbidden response has a 4xx status code
func (o *DynamicClientRegistrationDeleteClientForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this dynamic client registration delete client forbidden response has a 5xx status code
func (o *DynamicClientRegistrationDeleteClientForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration delete client forbidden response a status code equal to that given
func (o *DynamicClientRegistrationDeleteClientForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the dynamic client registration delete client forbidden response
func (o *DynamicClientRegistrationDeleteClientForbidden) Code() int {
	return 403
}

func (o *DynamicClientRegistrationDeleteClientForbidden) Error() string {
	return fmt.Sprintf("[DELETE /oauth2/register/{cid}][%d] dynamicClientRegistrationDeleteClientForbidden  %+v", 403, o.Payload)
}

func (o *DynamicClientRegistrationDeleteClientForbidden) String() string {
	return fmt.Sprintf("[DELETE /oauth2/register/{cid}][%d] dynamicClientRegistrationDeleteClientForbidden  %+v", 403, o.Payload)
}

func (o *DynamicClientRegistrationDeleteClientForbidden) GetPayload() *models.RFC6749Error {
	return o.Payload
}

func (o *DynamicClientRegistrationDeleteClientForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RFC6749Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationDeleteClientNotFound creates a DynamicClientRegistrationDeleteClientNotFound with default headers values
func NewDynamicClientRegistrationDeleteClientNotFound() *DynamicClientRegistrationDeleteClientNotFound {
	return &DynamicClientRegistrationDeleteClientNotFound{}
}

/*
DynamicClientRegistrationDeleteClientNotFound describes a response with status code 404, with default header values.

ErrorResponse
*/
type DynamicClientRegistrationDeleteClientNotFound struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this dynamic client registration delete client not found response has a 2xx status code
func (o *DynamicClientRegistrationDeleteClientNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this dynamic client registration delete client not found response has a 3xx status code
func (o *DynamicClientRegistrationDeleteClientNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration delete client not found response has a 4xx status code
func (o *DynamicClientRegistrationDeleteClientNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this dynamic client registration delete client not found response has a 5xx status code
func (o *DynamicClientRegistrationDeleteClientNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration delete client not found response a status code equal to that given
func (o *DynamicClientRegistrationDeleteClientNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the dynamic client registration delete client not found response
func (o *DynamicClientRegistrationDeleteClientNotFound) Code() int {
	return 404
}

func (o *DynamicClientRegistrationDeleteClientNotFound) Error() string {
	return fmt.Sprintf("[DELETE /oauth2/register/{cid}][%d] dynamicClientRegistrationDeleteClientNotFound  %+v", 404, o.Payload)
}

func (o *DynamicClientRegistrationDeleteClientNotFound) String() string {
	return fmt.Sprintf("[DELETE /oauth2/register/{cid}][%d] dynamicClientRegistrationDeleteClientNotFound  %+v", 404, o.Payload)
}

func (o *DynamicClientRegistrationDeleteClientNotFound) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *DynamicClientRegistrationDeleteClientNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
