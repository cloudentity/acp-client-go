// Code generated by go-swagger; DO NOT EDIT.

package oauth2

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/models"
)

// DynamicClientRegistrationOpenbankingUKUpdateClientReader is a Reader for the DynamicClientRegistrationOpenbankingUKUpdateClient structure.
type DynamicClientRegistrationOpenbankingUKUpdateClientReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DynamicClientRegistrationOpenbankingUKUpdateClientReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDynamicClientRegistrationOpenbankingUKUpdateClientOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDynamicClientRegistrationOpenbankingUKUpdateClientBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewDynamicClientRegistrationOpenbankingUKUpdateClientUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDynamicClientRegistrationOpenbankingUKUpdateClientForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDynamicClientRegistrationOpenbankingUKUpdateClientNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewDynamicClientRegistrationOpenbankingUKUpdateClientOK creates a DynamicClientRegistrationOpenbankingUKUpdateClientOK with default headers values
func NewDynamicClientRegistrationOpenbankingUKUpdateClientOK() *DynamicClientRegistrationOpenbankingUKUpdateClientOK {
	return &DynamicClientRegistrationOpenbankingUKUpdateClientOK{}
}

/* DynamicClientRegistrationOpenbankingUKUpdateClientOK describes a response with status code 200, with default header values.

OpenbankingUKDynamicClientRegistrationResponse
*/
type DynamicClientRegistrationOpenbankingUKUpdateClientOK struct {
	Payload *models.OpenbankingUKDynamicClientRegistrationResponse
}

func (o *DynamicClientRegistrationOpenbankingUKUpdateClientOK) Error() string {
	return fmt.Sprintf("[PUT /{tid}/{aid}/openbankinguk/dcr/v3.2/register/{cid}][%d] dynamicClientRegistrationOpenbankingUKUpdateClientOK  %+v", 200, o.Payload)
}
func (o *DynamicClientRegistrationOpenbankingUKUpdateClientOK) GetPayload() *models.OpenbankingUKDynamicClientRegistrationResponse {
	return o.Payload
}

func (o *DynamicClientRegistrationOpenbankingUKUpdateClientOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OpenbankingUKDynamicClientRegistrationResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationOpenbankingUKUpdateClientBadRequest creates a DynamicClientRegistrationOpenbankingUKUpdateClientBadRequest with default headers values
func NewDynamicClientRegistrationOpenbankingUKUpdateClientBadRequest() *DynamicClientRegistrationOpenbankingUKUpdateClientBadRequest {
	return &DynamicClientRegistrationOpenbankingUKUpdateClientBadRequest{}
}

/* DynamicClientRegistrationOpenbankingUKUpdateClientBadRequest describes a response with status code 400, with default header values.

RFC6749Error
*/
type DynamicClientRegistrationOpenbankingUKUpdateClientBadRequest struct {
	Payload *models.RFC6749Error
}

func (o *DynamicClientRegistrationOpenbankingUKUpdateClientBadRequest) Error() string {
	return fmt.Sprintf("[PUT /{tid}/{aid}/openbankinguk/dcr/v3.2/register/{cid}][%d] dynamicClientRegistrationOpenbankingUKUpdateClientBadRequest  %+v", 400, o.Payload)
}
func (o *DynamicClientRegistrationOpenbankingUKUpdateClientBadRequest) GetPayload() *models.RFC6749Error {
	return o.Payload
}

func (o *DynamicClientRegistrationOpenbankingUKUpdateClientBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RFC6749Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationOpenbankingUKUpdateClientUnauthorized creates a DynamicClientRegistrationOpenbankingUKUpdateClientUnauthorized with default headers values
func NewDynamicClientRegistrationOpenbankingUKUpdateClientUnauthorized() *DynamicClientRegistrationOpenbankingUKUpdateClientUnauthorized {
	return &DynamicClientRegistrationOpenbankingUKUpdateClientUnauthorized{}
}

/* DynamicClientRegistrationOpenbankingUKUpdateClientUnauthorized describes a response with status code 401, with default header values.

RFC6749Error
*/
type DynamicClientRegistrationOpenbankingUKUpdateClientUnauthorized struct {
	Payload *models.RFC6749Error
}

func (o *DynamicClientRegistrationOpenbankingUKUpdateClientUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /{tid}/{aid}/openbankinguk/dcr/v3.2/register/{cid}][%d] dynamicClientRegistrationOpenbankingUKUpdateClientUnauthorized  %+v", 401, o.Payload)
}
func (o *DynamicClientRegistrationOpenbankingUKUpdateClientUnauthorized) GetPayload() *models.RFC6749Error {
	return o.Payload
}

func (o *DynamicClientRegistrationOpenbankingUKUpdateClientUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RFC6749Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationOpenbankingUKUpdateClientForbidden creates a DynamicClientRegistrationOpenbankingUKUpdateClientForbidden with default headers values
func NewDynamicClientRegistrationOpenbankingUKUpdateClientForbidden() *DynamicClientRegistrationOpenbankingUKUpdateClientForbidden {
	return &DynamicClientRegistrationOpenbankingUKUpdateClientForbidden{}
}

/* DynamicClientRegistrationOpenbankingUKUpdateClientForbidden describes a response with status code 403, with default header values.

RFC6749Error
*/
type DynamicClientRegistrationOpenbankingUKUpdateClientForbidden struct {
	Payload *models.RFC6749Error
}

func (o *DynamicClientRegistrationOpenbankingUKUpdateClientForbidden) Error() string {
	return fmt.Sprintf("[PUT /{tid}/{aid}/openbankinguk/dcr/v3.2/register/{cid}][%d] dynamicClientRegistrationOpenbankingUKUpdateClientForbidden  %+v", 403, o.Payload)
}
func (o *DynamicClientRegistrationOpenbankingUKUpdateClientForbidden) GetPayload() *models.RFC6749Error {
	return o.Payload
}

func (o *DynamicClientRegistrationOpenbankingUKUpdateClientForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RFC6749Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDynamicClientRegistrationOpenbankingUKUpdateClientNotFound creates a DynamicClientRegistrationOpenbankingUKUpdateClientNotFound with default headers values
func NewDynamicClientRegistrationOpenbankingUKUpdateClientNotFound() *DynamicClientRegistrationOpenbankingUKUpdateClientNotFound {
	return &DynamicClientRegistrationOpenbankingUKUpdateClientNotFound{}
}

/* DynamicClientRegistrationOpenbankingUKUpdateClientNotFound describes a response with status code 404, with default header values.

genericError
*/
type DynamicClientRegistrationOpenbankingUKUpdateClientNotFound struct {
	Payload *models.GenericError
}

func (o *DynamicClientRegistrationOpenbankingUKUpdateClientNotFound) Error() string {
	return fmt.Sprintf("[PUT /{tid}/{aid}/openbankinguk/dcr/v3.2/register/{cid}][%d] dynamicClientRegistrationOpenbankingUKUpdateClientNotFound  %+v", 404, o.Payload)
}
func (o *DynamicClientRegistrationOpenbankingUKUpdateClientNotFound) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *DynamicClientRegistrationOpenbankingUKUpdateClientNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
