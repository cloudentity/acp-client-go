// Code generated by go-swagger; DO NOT EDIT.

package clients

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/models"
)

// UpdateClientReader is a Reader for the UpdateClient structure.
type UpdateClientReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateClientReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateClientOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateClientBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewUpdateClientUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdateClientForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateClientNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewUpdateClientUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewUpdateClientOK creates a UpdateClientOK with default headers values
func NewUpdateClientOK() *UpdateClientOK {
	return &UpdateClientOK{}
}

/*UpdateClientOK handles this case with default header values.

ClientAdminResponse
*/
type UpdateClientOK struct {
	Payload *models.ClientAdminResponse
}

func (o *UpdateClientOK) Error() string {
	return fmt.Sprintf("[PUT /api/admin/{tid}/clients/{cid}][%d] updateClientOK  %+v", 200, o.Payload)
}

func (o *UpdateClientOK) GetPayload() *models.ClientAdminResponse {
	return o.Payload
}

func (o *UpdateClientOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ClientAdminResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateClientBadRequest creates a UpdateClientBadRequest with default headers values
func NewUpdateClientBadRequest() *UpdateClientBadRequest {
	return &UpdateClientBadRequest{}
}

/*UpdateClientBadRequest handles this case with default header values.

HttpError
*/
type UpdateClientBadRequest struct {
	Payload *models.Error
}

func (o *UpdateClientBadRequest) Error() string {
	return fmt.Sprintf("[PUT /api/admin/{tid}/clients/{cid}][%d] updateClientBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateClientBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateClientBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateClientUnauthorized creates a UpdateClientUnauthorized with default headers values
func NewUpdateClientUnauthorized() *UpdateClientUnauthorized {
	return &UpdateClientUnauthorized{}
}

/*UpdateClientUnauthorized handles this case with default header values.

HttpError
*/
type UpdateClientUnauthorized struct {
	Payload *models.Error
}

func (o *UpdateClientUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /api/admin/{tid}/clients/{cid}][%d] updateClientUnauthorized  %+v", 401, o.Payload)
}

func (o *UpdateClientUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateClientUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateClientForbidden creates a UpdateClientForbidden with default headers values
func NewUpdateClientForbidden() *UpdateClientForbidden {
	return &UpdateClientForbidden{}
}

/*UpdateClientForbidden handles this case with default header values.

HttpError
*/
type UpdateClientForbidden struct {
	Payload *models.Error
}

func (o *UpdateClientForbidden) Error() string {
	return fmt.Sprintf("[PUT /api/admin/{tid}/clients/{cid}][%d] updateClientForbidden  %+v", 403, o.Payload)
}

func (o *UpdateClientForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateClientForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateClientNotFound creates a UpdateClientNotFound with default headers values
func NewUpdateClientNotFound() *UpdateClientNotFound {
	return &UpdateClientNotFound{}
}

/*UpdateClientNotFound handles this case with default header values.

HttpError
*/
type UpdateClientNotFound struct {
	Payload *models.Error
}

func (o *UpdateClientNotFound) Error() string {
	return fmt.Sprintf("[PUT /api/admin/{tid}/clients/{cid}][%d] updateClientNotFound  %+v", 404, o.Payload)
}

func (o *UpdateClientNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateClientNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateClientUnprocessableEntity creates a UpdateClientUnprocessableEntity with default headers values
func NewUpdateClientUnprocessableEntity() *UpdateClientUnprocessableEntity {
	return &UpdateClientUnprocessableEntity{}
}

/*UpdateClientUnprocessableEntity handles this case with default header values.

HttpError
*/
type UpdateClientUnprocessableEntity struct {
	Payload *models.Error
}

func (o *UpdateClientUnprocessableEntity) Error() string {
	return fmt.Sprintf("[PUT /api/admin/{tid}/clients/{cid}][%d] updateClientUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *UpdateClientUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateClientUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
