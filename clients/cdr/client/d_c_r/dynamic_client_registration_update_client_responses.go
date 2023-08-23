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

// DynamicClientRegistrationUpdateClientReader is a Reader for the DynamicClientRegistrationUpdateClient structure.
type DynamicClientRegistrationUpdateClientReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DynamicClientRegistrationUpdateClientReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDynamicClientRegistrationUpdateClientOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDynamicClientRegistrationUpdateClientBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewDynamicClientRegistrationUpdateClientUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDynamicClientRegistrationUpdateClientForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDynamicClientRegistrationUpdateClientNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewDynamicClientRegistrationUpdateClientOK creates a DynamicClientRegistrationUpdateClientOK with default headers values
func NewDynamicClientRegistrationUpdateClientOK() *DynamicClientRegistrationUpdateClientOK {
	return &DynamicClientRegistrationUpdateClientOK{}
}

/*
DynamicClientRegistrationUpdateClientOK describes a response with status code 200, with default header values.

Dynamic client registration response
*/
type DynamicClientRegistrationUpdateClientOK struct {
	Payload *models.CDRDynamicClientRegistrationResponse
}

// IsSuccess returns true when this dynamic client registration update client o k response has a 2xx status code
func (o *DynamicClientRegistrationUpdateClientOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this dynamic client registration update client o k response has a 3xx status code
func (o *DynamicClientRegistrationUpdateClientOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration update client o k response has a 4xx status code
func (o *DynamicClientRegistrationUpdateClientOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this dynamic client registration update client o k response has a 5xx status code
func (o *DynamicClientRegistrationUpdateClientOK) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration update client o k response a status code equal to that given
func (o *DynamicClientRegistrationUpdateClientOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the dynamic client registration update client o k response
func (o *DynamicClientRegistrationUpdateClientOK) Code() int {
	return 200
}

func (o *DynamicClientRegistrationUpdateClientOK) Error() string {
	return fmt.Sprintf("[PUT /oauth2/register/{cid}][%d] dynamicClientRegistrationUpdateClientOK  %+v", 200, o.Payload)
}

func (o *DynamicClientRegistrationUpdateClientOK) String() string {
	return fmt.Sprintf("[PUT /oauth2/register/{cid}][%d] dynamicClientRegistrationUpdateClientOK  %+v", 200, o.Payload)
}

func (o *DynamicClientRegistrationUpdateClientOK) GetPayload() *models.CDRDynamicClientRegistrationResponse {
	return o.Payload
}

func (o *DynamicClientRegistrationUpdateClientOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.CDRDynamicClientRegistrationResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationUpdateClientBadRequest creates a DynamicClientRegistrationUpdateClientBadRequest with default headers values
func NewDynamicClientRegistrationUpdateClientBadRequest() *DynamicClientRegistrationUpdateClientBadRequest {
	return &DynamicClientRegistrationUpdateClientBadRequest{}
}

/*
DynamicClientRegistrationUpdateClientBadRequest describes a response with status code 400, with default header values.

RFC6749 error
*/
type DynamicClientRegistrationUpdateClientBadRequest struct {
	Payload *models.RFC6749Error
}

// IsSuccess returns true when this dynamic client registration update client bad request response has a 2xx status code
func (o *DynamicClientRegistrationUpdateClientBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this dynamic client registration update client bad request response has a 3xx status code
func (o *DynamicClientRegistrationUpdateClientBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration update client bad request response has a 4xx status code
func (o *DynamicClientRegistrationUpdateClientBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this dynamic client registration update client bad request response has a 5xx status code
func (o *DynamicClientRegistrationUpdateClientBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration update client bad request response a status code equal to that given
func (o *DynamicClientRegistrationUpdateClientBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the dynamic client registration update client bad request response
func (o *DynamicClientRegistrationUpdateClientBadRequest) Code() int {
	return 400
}

func (o *DynamicClientRegistrationUpdateClientBadRequest) Error() string {
	return fmt.Sprintf("[PUT /oauth2/register/{cid}][%d] dynamicClientRegistrationUpdateClientBadRequest  %+v", 400, o.Payload)
}

func (o *DynamicClientRegistrationUpdateClientBadRequest) String() string {
	return fmt.Sprintf("[PUT /oauth2/register/{cid}][%d] dynamicClientRegistrationUpdateClientBadRequest  %+v", 400, o.Payload)
}

func (o *DynamicClientRegistrationUpdateClientBadRequest) GetPayload() *models.RFC6749Error {
	return o.Payload
}

func (o *DynamicClientRegistrationUpdateClientBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RFC6749Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationUpdateClientUnauthorized creates a DynamicClientRegistrationUpdateClientUnauthorized with default headers values
func NewDynamicClientRegistrationUpdateClientUnauthorized() *DynamicClientRegistrationUpdateClientUnauthorized {
	return &DynamicClientRegistrationUpdateClientUnauthorized{}
}

/*
DynamicClientRegistrationUpdateClientUnauthorized describes a response with status code 401, with default header values.

RFC6749 error
*/
type DynamicClientRegistrationUpdateClientUnauthorized struct {
	Payload *models.RFC6749Error
}

// IsSuccess returns true when this dynamic client registration update client unauthorized response has a 2xx status code
func (o *DynamicClientRegistrationUpdateClientUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this dynamic client registration update client unauthorized response has a 3xx status code
func (o *DynamicClientRegistrationUpdateClientUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration update client unauthorized response has a 4xx status code
func (o *DynamicClientRegistrationUpdateClientUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this dynamic client registration update client unauthorized response has a 5xx status code
func (o *DynamicClientRegistrationUpdateClientUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration update client unauthorized response a status code equal to that given
func (o *DynamicClientRegistrationUpdateClientUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the dynamic client registration update client unauthorized response
func (o *DynamicClientRegistrationUpdateClientUnauthorized) Code() int {
	return 401
}

func (o *DynamicClientRegistrationUpdateClientUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /oauth2/register/{cid}][%d] dynamicClientRegistrationUpdateClientUnauthorized  %+v", 401, o.Payload)
}

func (o *DynamicClientRegistrationUpdateClientUnauthorized) String() string {
	return fmt.Sprintf("[PUT /oauth2/register/{cid}][%d] dynamicClientRegistrationUpdateClientUnauthorized  %+v", 401, o.Payload)
}

func (o *DynamicClientRegistrationUpdateClientUnauthorized) GetPayload() *models.RFC6749Error {
	return o.Payload
}

func (o *DynamicClientRegistrationUpdateClientUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RFC6749Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationUpdateClientForbidden creates a DynamicClientRegistrationUpdateClientForbidden with default headers values
func NewDynamicClientRegistrationUpdateClientForbidden() *DynamicClientRegistrationUpdateClientForbidden {
	return &DynamicClientRegistrationUpdateClientForbidden{}
}

/*
DynamicClientRegistrationUpdateClientForbidden describes a response with status code 403, with default header values.

RFC6749 error
*/
type DynamicClientRegistrationUpdateClientForbidden struct {
	Payload *models.RFC6749Error
}

// IsSuccess returns true when this dynamic client registration update client forbidden response has a 2xx status code
func (o *DynamicClientRegistrationUpdateClientForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this dynamic client registration update client forbidden response has a 3xx status code
func (o *DynamicClientRegistrationUpdateClientForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration update client forbidden response has a 4xx status code
func (o *DynamicClientRegistrationUpdateClientForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this dynamic client registration update client forbidden response has a 5xx status code
func (o *DynamicClientRegistrationUpdateClientForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration update client forbidden response a status code equal to that given
func (o *DynamicClientRegistrationUpdateClientForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the dynamic client registration update client forbidden response
func (o *DynamicClientRegistrationUpdateClientForbidden) Code() int {
	return 403
}

func (o *DynamicClientRegistrationUpdateClientForbidden) Error() string {
	return fmt.Sprintf("[PUT /oauth2/register/{cid}][%d] dynamicClientRegistrationUpdateClientForbidden  %+v", 403, o.Payload)
}

func (o *DynamicClientRegistrationUpdateClientForbidden) String() string {
	return fmt.Sprintf("[PUT /oauth2/register/{cid}][%d] dynamicClientRegistrationUpdateClientForbidden  %+v", 403, o.Payload)
}

func (o *DynamicClientRegistrationUpdateClientForbidden) GetPayload() *models.RFC6749Error {
	return o.Payload
}

func (o *DynamicClientRegistrationUpdateClientForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RFC6749Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationUpdateClientNotFound creates a DynamicClientRegistrationUpdateClientNotFound with default headers values
func NewDynamicClientRegistrationUpdateClientNotFound() *DynamicClientRegistrationUpdateClientNotFound {
	return &DynamicClientRegistrationUpdateClientNotFound{}
}

/*
DynamicClientRegistrationUpdateClientNotFound describes a response with status code 404, with default header values.

ErrorResponse
*/
type DynamicClientRegistrationUpdateClientNotFound struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this dynamic client registration update client not found response has a 2xx status code
func (o *DynamicClientRegistrationUpdateClientNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this dynamic client registration update client not found response has a 3xx status code
func (o *DynamicClientRegistrationUpdateClientNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration update client not found response has a 4xx status code
func (o *DynamicClientRegistrationUpdateClientNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this dynamic client registration update client not found response has a 5xx status code
func (o *DynamicClientRegistrationUpdateClientNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration update client not found response a status code equal to that given
func (o *DynamicClientRegistrationUpdateClientNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the dynamic client registration update client not found response
func (o *DynamicClientRegistrationUpdateClientNotFound) Code() int {
	return 404
}

func (o *DynamicClientRegistrationUpdateClientNotFound) Error() string {
	return fmt.Sprintf("[PUT /oauth2/register/{cid}][%d] dynamicClientRegistrationUpdateClientNotFound  %+v", 404, o.Payload)
}

func (o *DynamicClientRegistrationUpdateClientNotFound) String() string {
	return fmt.Sprintf("[PUT /oauth2/register/{cid}][%d] dynamicClientRegistrationUpdateClientNotFound  %+v", 404, o.Payload)
}

func (o *DynamicClientRegistrationUpdateClientNotFound) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *DynamicClientRegistrationUpdateClientNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}