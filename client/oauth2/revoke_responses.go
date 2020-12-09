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

// RevokeReader is a Reader for the Revoke structure.
type RevokeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RevokeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRevokeOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewRevokeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRevokeNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewRevokeOK creates a RevokeOK with default headers values
func NewRevokeOK() *RevokeOK {
	return &RevokeOK{}
}

/*RevokeOK handles this case with default header values.

emptyResponse
*/
type RevokeOK struct {
	Payload models.EmptyResponse
}

func (o *RevokeOK) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/oauth2/revoke][%d] revokeOK  %+v", 200, o.Payload)
}

func (o *RevokeOK) GetPayload() models.EmptyResponse {
	return o.Payload
}

func (o *RevokeOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeUnauthorized creates a RevokeUnauthorized with default headers values
func NewRevokeUnauthorized() *RevokeUnauthorized {
	return &RevokeUnauthorized{}
}

/*RevokeUnauthorized handles this case with default header values.

genericError
*/
type RevokeUnauthorized struct {
	Payload *models.GenericError
}

func (o *RevokeUnauthorized) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/oauth2/revoke][%d] revokeUnauthorized  %+v", 401, o.Payload)
}

func (o *RevokeUnauthorized) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *RevokeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeNotFound creates a RevokeNotFound with default headers values
func NewRevokeNotFound() *RevokeNotFound {
	return &RevokeNotFound{}
}

/*RevokeNotFound handles this case with default header values.

genericError
*/
type RevokeNotFound struct {
	Payload *models.GenericError
}

func (o *RevokeNotFound) Error() string {
	return fmt.Sprintf("[POST /{tid}/{aid}/oauth2/revoke][%d] revokeNotFound  %+v", 404, o.Payload)
}

func (o *RevokeNotFound) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *RevokeNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
