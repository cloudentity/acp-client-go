// Code generated by go-swagger; DO NOT EDIT.

package d_c_r

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/obuk/models"
)

// DynamicClientRegistrationOpenbankingUKGetClientReader is a Reader for the DynamicClientRegistrationOpenbankingUKGetClient structure.
type DynamicClientRegistrationOpenbankingUKGetClientReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DynamicClientRegistrationOpenbankingUKGetClientReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDynamicClientRegistrationOpenbankingUKGetClientOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDynamicClientRegistrationOpenbankingUKGetClientBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewDynamicClientRegistrationOpenbankingUKGetClientUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDynamicClientRegistrationOpenbankingUKGetClientForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDynamicClientRegistrationOpenbankingUKGetClientNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewDynamicClientRegistrationOpenbankingUKGetClientOK creates a DynamicClientRegistrationOpenbankingUKGetClientOK with default headers values
func NewDynamicClientRegistrationOpenbankingUKGetClientOK() *DynamicClientRegistrationOpenbankingUKGetClientOK {
	return &DynamicClientRegistrationOpenbankingUKGetClientOK{}
}

/*
DynamicClientRegistrationOpenbankingUKGetClientOK describes a response with status code 200, with default header values.

OpenbankingUK Dynamic Client Registration Update Client Response
*/
type DynamicClientRegistrationOpenbankingUKGetClientOK struct {
	Payload *models.OpenbankingUKDynamicClientRegistrationResponse
}

// IsSuccess returns true when this dynamic client registration openbanking u k get client o k response has a 2xx status code
func (o *DynamicClientRegistrationOpenbankingUKGetClientOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this dynamic client registration openbanking u k get client o k response has a 3xx status code
func (o *DynamicClientRegistrationOpenbankingUKGetClientOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration openbanking u k get client o k response has a 4xx status code
func (o *DynamicClientRegistrationOpenbankingUKGetClientOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this dynamic client registration openbanking u k get client o k response has a 5xx status code
func (o *DynamicClientRegistrationOpenbankingUKGetClientOK) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration openbanking u k get client o k response a status code equal to that given
func (o *DynamicClientRegistrationOpenbankingUKGetClientOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the dynamic client registration openbanking u k get client o k response
func (o *DynamicClientRegistrationOpenbankingUKGetClientOK) Code() int {
	return 200
}

func (o *DynamicClientRegistrationOpenbankingUKGetClientOK) Error() string {
	return fmt.Sprintf("[GET /openbankinguk/dcr/v3.2/register/{cid}][%d] dynamicClientRegistrationOpenbankingUKGetClientOK  %+v", 200, o.Payload)
}

func (o *DynamicClientRegistrationOpenbankingUKGetClientOK) String() string {
	return fmt.Sprintf("[GET /openbankinguk/dcr/v3.2/register/{cid}][%d] dynamicClientRegistrationOpenbankingUKGetClientOK  %+v", 200, o.Payload)
}

func (o *DynamicClientRegistrationOpenbankingUKGetClientOK) GetPayload() *models.OpenbankingUKDynamicClientRegistrationResponse {
	return o.Payload
}

func (o *DynamicClientRegistrationOpenbankingUKGetClientOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OpenbankingUKDynamicClientRegistrationResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationOpenbankingUKGetClientBadRequest creates a DynamicClientRegistrationOpenbankingUKGetClientBadRequest with default headers values
func NewDynamicClientRegistrationOpenbankingUKGetClientBadRequest() *DynamicClientRegistrationOpenbankingUKGetClientBadRequest {
	return &DynamicClientRegistrationOpenbankingUKGetClientBadRequest{}
}

/*
DynamicClientRegistrationOpenbankingUKGetClientBadRequest describes a response with status code 400, with default header values.

RFC6749 error
*/
type DynamicClientRegistrationOpenbankingUKGetClientBadRequest struct {
	Payload *models.RFC6749Error
}

// IsSuccess returns true when this dynamic client registration openbanking u k get client bad request response has a 2xx status code
func (o *DynamicClientRegistrationOpenbankingUKGetClientBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this dynamic client registration openbanking u k get client bad request response has a 3xx status code
func (o *DynamicClientRegistrationOpenbankingUKGetClientBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration openbanking u k get client bad request response has a 4xx status code
func (o *DynamicClientRegistrationOpenbankingUKGetClientBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this dynamic client registration openbanking u k get client bad request response has a 5xx status code
func (o *DynamicClientRegistrationOpenbankingUKGetClientBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration openbanking u k get client bad request response a status code equal to that given
func (o *DynamicClientRegistrationOpenbankingUKGetClientBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the dynamic client registration openbanking u k get client bad request response
func (o *DynamicClientRegistrationOpenbankingUKGetClientBadRequest) Code() int {
	return 400
}

func (o *DynamicClientRegistrationOpenbankingUKGetClientBadRequest) Error() string {
	return fmt.Sprintf("[GET /openbankinguk/dcr/v3.2/register/{cid}][%d] dynamicClientRegistrationOpenbankingUKGetClientBadRequest  %+v", 400, o.Payload)
}

func (o *DynamicClientRegistrationOpenbankingUKGetClientBadRequest) String() string {
	return fmt.Sprintf("[GET /openbankinguk/dcr/v3.2/register/{cid}][%d] dynamicClientRegistrationOpenbankingUKGetClientBadRequest  %+v", 400, o.Payload)
}

func (o *DynamicClientRegistrationOpenbankingUKGetClientBadRequest) GetPayload() *models.RFC6749Error {
	return o.Payload
}

func (o *DynamicClientRegistrationOpenbankingUKGetClientBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RFC6749Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationOpenbankingUKGetClientUnauthorized creates a DynamicClientRegistrationOpenbankingUKGetClientUnauthorized with default headers values
func NewDynamicClientRegistrationOpenbankingUKGetClientUnauthorized() *DynamicClientRegistrationOpenbankingUKGetClientUnauthorized {
	return &DynamicClientRegistrationOpenbankingUKGetClientUnauthorized{}
}

/*
DynamicClientRegistrationOpenbankingUKGetClientUnauthorized describes a response with status code 401, with default header values.

RFC6749 error
*/
type DynamicClientRegistrationOpenbankingUKGetClientUnauthorized struct {
	Payload *models.RFC6749Error
}

// IsSuccess returns true when this dynamic client registration openbanking u k get client unauthorized response has a 2xx status code
func (o *DynamicClientRegistrationOpenbankingUKGetClientUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this dynamic client registration openbanking u k get client unauthorized response has a 3xx status code
func (o *DynamicClientRegistrationOpenbankingUKGetClientUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration openbanking u k get client unauthorized response has a 4xx status code
func (o *DynamicClientRegistrationOpenbankingUKGetClientUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this dynamic client registration openbanking u k get client unauthorized response has a 5xx status code
func (o *DynamicClientRegistrationOpenbankingUKGetClientUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration openbanking u k get client unauthorized response a status code equal to that given
func (o *DynamicClientRegistrationOpenbankingUKGetClientUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the dynamic client registration openbanking u k get client unauthorized response
func (o *DynamicClientRegistrationOpenbankingUKGetClientUnauthorized) Code() int {
	return 401
}

func (o *DynamicClientRegistrationOpenbankingUKGetClientUnauthorized) Error() string {
	return fmt.Sprintf("[GET /openbankinguk/dcr/v3.2/register/{cid}][%d] dynamicClientRegistrationOpenbankingUKGetClientUnauthorized  %+v", 401, o.Payload)
}

func (o *DynamicClientRegistrationOpenbankingUKGetClientUnauthorized) String() string {
	return fmt.Sprintf("[GET /openbankinguk/dcr/v3.2/register/{cid}][%d] dynamicClientRegistrationOpenbankingUKGetClientUnauthorized  %+v", 401, o.Payload)
}

func (o *DynamicClientRegistrationOpenbankingUKGetClientUnauthorized) GetPayload() *models.RFC6749Error {
	return o.Payload
}

func (o *DynamicClientRegistrationOpenbankingUKGetClientUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RFC6749Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationOpenbankingUKGetClientForbidden creates a DynamicClientRegistrationOpenbankingUKGetClientForbidden with default headers values
func NewDynamicClientRegistrationOpenbankingUKGetClientForbidden() *DynamicClientRegistrationOpenbankingUKGetClientForbidden {
	return &DynamicClientRegistrationOpenbankingUKGetClientForbidden{}
}

/*
DynamicClientRegistrationOpenbankingUKGetClientForbidden describes a response with status code 403, with default header values.

RFC6749 error
*/
type DynamicClientRegistrationOpenbankingUKGetClientForbidden struct {
	Payload *models.RFC6749Error
}

// IsSuccess returns true when this dynamic client registration openbanking u k get client forbidden response has a 2xx status code
func (o *DynamicClientRegistrationOpenbankingUKGetClientForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this dynamic client registration openbanking u k get client forbidden response has a 3xx status code
func (o *DynamicClientRegistrationOpenbankingUKGetClientForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration openbanking u k get client forbidden response has a 4xx status code
func (o *DynamicClientRegistrationOpenbankingUKGetClientForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this dynamic client registration openbanking u k get client forbidden response has a 5xx status code
func (o *DynamicClientRegistrationOpenbankingUKGetClientForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration openbanking u k get client forbidden response a status code equal to that given
func (o *DynamicClientRegistrationOpenbankingUKGetClientForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the dynamic client registration openbanking u k get client forbidden response
func (o *DynamicClientRegistrationOpenbankingUKGetClientForbidden) Code() int {
	return 403
}

func (o *DynamicClientRegistrationOpenbankingUKGetClientForbidden) Error() string {
	return fmt.Sprintf("[GET /openbankinguk/dcr/v3.2/register/{cid}][%d] dynamicClientRegistrationOpenbankingUKGetClientForbidden  %+v", 403, o.Payload)
}

func (o *DynamicClientRegistrationOpenbankingUKGetClientForbidden) String() string {
	return fmt.Sprintf("[GET /openbankinguk/dcr/v3.2/register/{cid}][%d] dynamicClientRegistrationOpenbankingUKGetClientForbidden  %+v", 403, o.Payload)
}

func (o *DynamicClientRegistrationOpenbankingUKGetClientForbidden) GetPayload() *models.RFC6749Error {
	return o.Payload
}

func (o *DynamicClientRegistrationOpenbankingUKGetClientForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RFC6749Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationOpenbankingUKGetClientNotFound creates a DynamicClientRegistrationOpenbankingUKGetClientNotFound with default headers values
func NewDynamicClientRegistrationOpenbankingUKGetClientNotFound() *DynamicClientRegistrationOpenbankingUKGetClientNotFound {
	return &DynamicClientRegistrationOpenbankingUKGetClientNotFound{}
}

/*
DynamicClientRegistrationOpenbankingUKGetClientNotFound describes a response with status code 404, with default header values.

ErrorResponse
*/
type DynamicClientRegistrationOpenbankingUKGetClientNotFound struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this dynamic client registration openbanking u k get client not found response has a 2xx status code
func (o *DynamicClientRegistrationOpenbankingUKGetClientNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this dynamic client registration openbanking u k get client not found response has a 3xx status code
func (o *DynamicClientRegistrationOpenbankingUKGetClientNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration openbanking u k get client not found response has a 4xx status code
func (o *DynamicClientRegistrationOpenbankingUKGetClientNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this dynamic client registration openbanking u k get client not found response has a 5xx status code
func (o *DynamicClientRegistrationOpenbankingUKGetClientNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration openbanking u k get client not found response a status code equal to that given
func (o *DynamicClientRegistrationOpenbankingUKGetClientNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the dynamic client registration openbanking u k get client not found response
func (o *DynamicClientRegistrationOpenbankingUKGetClientNotFound) Code() int {
	return 404
}

func (o *DynamicClientRegistrationOpenbankingUKGetClientNotFound) Error() string {
	return fmt.Sprintf("[GET /openbankinguk/dcr/v3.2/register/{cid}][%d] dynamicClientRegistrationOpenbankingUKGetClientNotFound  %+v", 404, o.Payload)
}

func (o *DynamicClientRegistrationOpenbankingUKGetClientNotFound) String() string {
	return fmt.Sprintf("[GET /openbankinguk/dcr/v3.2/register/{cid}][%d] dynamicClientRegistrationOpenbankingUKGetClientNotFound  %+v", 404, o.Payload)
}

func (o *DynamicClientRegistrationOpenbankingUKGetClientNotFound) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *DynamicClientRegistrationOpenbankingUKGetClientNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
