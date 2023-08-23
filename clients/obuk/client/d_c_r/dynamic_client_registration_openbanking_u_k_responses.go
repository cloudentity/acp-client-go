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

// DynamicClientRegistrationOpenbankingUKReader is a Reader for the DynamicClientRegistrationOpenbankingUK structure.
type DynamicClientRegistrationOpenbankingUKReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DynamicClientRegistrationOpenbankingUKReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewDynamicClientRegistrationOpenbankingUKCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDynamicClientRegistrationOpenbankingUKBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewDynamicClientRegistrationOpenbankingUKUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDynamicClientRegistrationOpenbankingUKForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDynamicClientRegistrationOpenbankingUKNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewDynamicClientRegistrationOpenbankingUKCreated creates a DynamicClientRegistrationOpenbankingUKCreated with default headers values
func NewDynamicClientRegistrationOpenbankingUKCreated() *DynamicClientRegistrationOpenbankingUKCreated {
	return &DynamicClientRegistrationOpenbankingUKCreated{}
}

/*
DynamicClientRegistrationOpenbankingUKCreated describes a response with status code 201, with default header values.

OpenbankingUK Dynamic Client Registration Update Client Response
*/
type DynamicClientRegistrationOpenbankingUKCreated struct {
	Payload *models.OpenbankingUKDynamicClientRegistrationResponse
}

// IsSuccess returns true when this dynamic client registration openbanking u k created response has a 2xx status code
func (o *DynamicClientRegistrationOpenbankingUKCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this dynamic client registration openbanking u k created response has a 3xx status code
func (o *DynamicClientRegistrationOpenbankingUKCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration openbanking u k created response has a 4xx status code
func (o *DynamicClientRegistrationOpenbankingUKCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this dynamic client registration openbanking u k created response has a 5xx status code
func (o *DynamicClientRegistrationOpenbankingUKCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration openbanking u k created response a status code equal to that given
func (o *DynamicClientRegistrationOpenbankingUKCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the dynamic client registration openbanking u k created response
func (o *DynamicClientRegistrationOpenbankingUKCreated) Code() int {
	return 201
}

func (o *DynamicClientRegistrationOpenbankingUKCreated) Error() string {
	return fmt.Sprintf("[POST /openbankinguk/dcr/v3.2/register][%d] dynamicClientRegistrationOpenbankingUKCreated  %+v", 201, o.Payload)
}

func (o *DynamicClientRegistrationOpenbankingUKCreated) String() string {
	return fmt.Sprintf("[POST /openbankinguk/dcr/v3.2/register][%d] dynamicClientRegistrationOpenbankingUKCreated  %+v", 201, o.Payload)
}

func (o *DynamicClientRegistrationOpenbankingUKCreated) GetPayload() *models.OpenbankingUKDynamicClientRegistrationResponse {
	return o.Payload
}

func (o *DynamicClientRegistrationOpenbankingUKCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OpenbankingUKDynamicClientRegistrationResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationOpenbankingUKBadRequest creates a DynamicClientRegistrationOpenbankingUKBadRequest with default headers values
func NewDynamicClientRegistrationOpenbankingUKBadRequest() *DynamicClientRegistrationOpenbankingUKBadRequest {
	return &DynamicClientRegistrationOpenbankingUKBadRequest{}
}

/*
DynamicClientRegistrationOpenbankingUKBadRequest describes a response with status code 400, with default header values.

RFC6749 error
*/
type DynamicClientRegistrationOpenbankingUKBadRequest struct {
	Payload *models.RFC6749Error
}

// IsSuccess returns true when this dynamic client registration openbanking u k bad request response has a 2xx status code
func (o *DynamicClientRegistrationOpenbankingUKBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this dynamic client registration openbanking u k bad request response has a 3xx status code
func (o *DynamicClientRegistrationOpenbankingUKBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration openbanking u k bad request response has a 4xx status code
func (o *DynamicClientRegistrationOpenbankingUKBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this dynamic client registration openbanking u k bad request response has a 5xx status code
func (o *DynamicClientRegistrationOpenbankingUKBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration openbanking u k bad request response a status code equal to that given
func (o *DynamicClientRegistrationOpenbankingUKBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the dynamic client registration openbanking u k bad request response
func (o *DynamicClientRegistrationOpenbankingUKBadRequest) Code() int {
	return 400
}

func (o *DynamicClientRegistrationOpenbankingUKBadRequest) Error() string {
	return fmt.Sprintf("[POST /openbankinguk/dcr/v3.2/register][%d] dynamicClientRegistrationOpenbankingUKBadRequest  %+v", 400, o.Payload)
}

func (o *DynamicClientRegistrationOpenbankingUKBadRequest) String() string {
	return fmt.Sprintf("[POST /openbankinguk/dcr/v3.2/register][%d] dynamicClientRegistrationOpenbankingUKBadRequest  %+v", 400, o.Payload)
}

func (o *DynamicClientRegistrationOpenbankingUKBadRequest) GetPayload() *models.RFC6749Error {
	return o.Payload
}

func (o *DynamicClientRegistrationOpenbankingUKBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RFC6749Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationOpenbankingUKUnauthorized creates a DynamicClientRegistrationOpenbankingUKUnauthorized with default headers values
func NewDynamicClientRegistrationOpenbankingUKUnauthorized() *DynamicClientRegistrationOpenbankingUKUnauthorized {
	return &DynamicClientRegistrationOpenbankingUKUnauthorized{}
}

/*
DynamicClientRegistrationOpenbankingUKUnauthorized describes a response with status code 401, with default header values.

RFC6749 error
*/
type DynamicClientRegistrationOpenbankingUKUnauthorized struct {
	Payload *models.RFC6749Error
}

// IsSuccess returns true when this dynamic client registration openbanking u k unauthorized response has a 2xx status code
func (o *DynamicClientRegistrationOpenbankingUKUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this dynamic client registration openbanking u k unauthorized response has a 3xx status code
func (o *DynamicClientRegistrationOpenbankingUKUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration openbanking u k unauthorized response has a 4xx status code
func (o *DynamicClientRegistrationOpenbankingUKUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this dynamic client registration openbanking u k unauthorized response has a 5xx status code
func (o *DynamicClientRegistrationOpenbankingUKUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration openbanking u k unauthorized response a status code equal to that given
func (o *DynamicClientRegistrationOpenbankingUKUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the dynamic client registration openbanking u k unauthorized response
func (o *DynamicClientRegistrationOpenbankingUKUnauthorized) Code() int {
	return 401
}

func (o *DynamicClientRegistrationOpenbankingUKUnauthorized) Error() string {
	return fmt.Sprintf("[POST /openbankinguk/dcr/v3.2/register][%d] dynamicClientRegistrationOpenbankingUKUnauthorized  %+v", 401, o.Payload)
}

func (o *DynamicClientRegistrationOpenbankingUKUnauthorized) String() string {
	return fmt.Sprintf("[POST /openbankinguk/dcr/v3.2/register][%d] dynamicClientRegistrationOpenbankingUKUnauthorized  %+v", 401, o.Payload)
}

func (o *DynamicClientRegistrationOpenbankingUKUnauthorized) GetPayload() *models.RFC6749Error {
	return o.Payload
}

func (o *DynamicClientRegistrationOpenbankingUKUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RFC6749Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationOpenbankingUKForbidden creates a DynamicClientRegistrationOpenbankingUKForbidden with default headers values
func NewDynamicClientRegistrationOpenbankingUKForbidden() *DynamicClientRegistrationOpenbankingUKForbidden {
	return &DynamicClientRegistrationOpenbankingUKForbidden{}
}

/*
DynamicClientRegistrationOpenbankingUKForbidden describes a response with status code 403, with default header values.

RFC6749 error
*/
type DynamicClientRegistrationOpenbankingUKForbidden struct {
	Payload *models.RFC6749Error
}

// IsSuccess returns true when this dynamic client registration openbanking u k forbidden response has a 2xx status code
func (o *DynamicClientRegistrationOpenbankingUKForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this dynamic client registration openbanking u k forbidden response has a 3xx status code
func (o *DynamicClientRegistrationOpenbankingUKForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration openbanking u k forbidden response has a 4xx status code
func (o *DynamicClientRegistrationOpenbankingUKForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this dynamic client registration openbanking u k forbidden response has a 5xx status code
func (o *DynamicClientRegistrationOpenbankingUKForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration openbanking u k forbidden response a status code equal to that given
func (o *DynamicClientRegistrationOpenbankingUKForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the dynamic client registration openbanking u k forbidden response
func (o *DynamicClientRegistrationOpenbankingUKForbidden) Code() int {
	return 403
}

func (o *DynamicClientRegistrationOpenbankingUKForbidden) Error() string {
	return fmt.Sprintf("[POST /openbankinguk/dcr/v3.2/register][%d] dynamicClientRegistrationOpenbankingUKForbidden  %+v", 403, o.Payload)
}

func (o *DynamicClientRegistrationOpenbankingUKForbidden) String() string {
	return fmt.Sprintf("[POST /openbankinguk/dcr/v3.2/register][%d] dynamicClientRegistrationOpenbankingUKForbidden  %+v", 403, o.Payload)
}

func (o *DynamicClientRegistrationOpenbankingUKForbidden) GetPayload() *models.RFC6749Error {
	return o.Payload
}

func (o *DynamicClientRegistrationOpenbankingUKForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RFC6749Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationOpenbankingUKNotFound creates a DynamicClientRegistrationOpenbankingUKNotFound with default headers values
func NewDynamicClientRegistrationOpenbankingUKNotFound() *DynamicClientRegistrationOpenbankingUKNotFound {
	return &DynamicClientRegistrationOpenbankingUKNotFound{}
}

/*
DynamicClientRegistrationOpenbankingUKNotFound describes a response with status code 404, with default header values.

ErrorResponse
*/
type DynamicClientRegistrationOpenbankingUKNotFound struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this dynamic client registration openbanking u k not found response has a 2xx status code
func (o *DynamicClientRegistrationOpenbankingUKNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this dynamic client registration openbanking u k not found response has a 3xx status code
func (o *DynamicClientRegistrationOpenbankingUKNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this dynamic client registration openbanking u k not found response has a 4xx status code
func (o *DynamicClientRegistrationOpenbankingUKNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this dynamic client registration openbanking u k not found response has a 5xx status code
func (o *DynamicClientRegistrationOpenbankingUKNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this dynamic client registration openbanking u k not found response a status code equal to that given
func (o *DynamicClientRegistrationOpenbankingUKNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the dynamic client registration openbanking u k not found response
func (o *DynamicClientRegistrationOpenbankingUKNotFound) Code() int {
	return 404
}

func (o *DynamicClientRegistrationOpenbankingUKNotFound) Error() string {
	return fmt.Sprintf("[POST /openbankinguk/dcr/v3.2/register][%d] dynamicClientRegistrationOpenbankingUKNotFound  %+v", 404, o.Payload)
}

func (o *DynamicClientRegistrationOpenbankingUKNotFound) String() string {
	return fmt.Sprintf("[POST /openbankinguk/dcr/v3.2/register][%d] dynamicClientRegistrationOpenbankingUKNotFound  %+v", 404, o.Payload)
}

func (o *DynamicClientRegistrationOpenbankingUKNotFound) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *DynamicClientRegistrationOpenbankingUKNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}