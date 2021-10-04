// Code generated by go-swagger; DO NOT EDIT.

package mfa_methods

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/models"
)

// UpdateMFAMethodReader is a Reader for the UpdateMFAMethod structure.
type UpdateMFAMethodReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateMFAMethodReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateMFAMethodOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateMFAMethodBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewUpdateMFAMethodUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdateMFAMethodForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateMFAMethodNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewUpdateMFAMethodConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewUpdateMFAMethodUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewUpdateMFAMethodOK creates a UpdateMFAMethodOK with default headers values
func NewUpdateMFAMethodOK() *UpdateMFAMethodOK {
	return &UpdateMFAMethodOK{}
}

/* UpdateMFAMethodOK describes a response with status code 200, with default header values.

MFAMethod
*/
type UpdateMFAMethodOK struct {
	Payload *models.MFAMethod
}

func (o *UpdateMFAMethodOK) Error() string {
	return fmt.Sprintf("[PUT /api/admin/{tid}/mfa-methods/{mfaID}][%d] updateMFAMethodOK  %+v", 200, o.Payload)
}
func (o *UpdateMFAMethodOK) GetPayload() *models.MFAMethod {
	return o.Payload
}

func (o *UpdateMFAMethodOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.MFAMethod)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateMFAMethodBadRequest creates a UpdateMFAMethodBadRequest with default headers values
func NewUpdateMFAMethodBadRequest() *UpdateMFAMethodBadRequest {
	return &UpdateMFAMethodBadRequest{}
}

/* UpdateMFAMethodBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type UpdateMFAMethodBadRequest struct {
	Payload *models.Error
}

func (o *UpdateMFAMethodBadRequest) Error() string {
	return fmt.Sprintf("[PUT /api/admin/{tid}/mfa-methods/{mfaID}][%d] updateMFAMethodBadRequest  %+v", 400, o.Payload)
}
func (o *UpdateMFAMethodBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateMFAMethodBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateMFAMethodUnauthorized creates a UpdateMFAMethodUnauthorized with default headers values
func NewUpdateMFAMethodUnauthorized() *UpdateMFAMethodUnauthorized {
	return &UpdateMFAMethodUnauthorized{}
}

/* UpdateMFAMethodUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type UpdateMFAMethodUnauthorized struct {
	Payload *models.Error
}

func (o *UpdateMFAMethodUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /api/admin/{tid}/mfa-methods/{mfaID}][%d] updateMFAMethodUnauthorized  %+v", 401, o.Payload)
}
func (o *UpdateMFAMethodUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateMFAMethodUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateMFAMethodForbidden creates a UpdateMFAMethodForbidden with default headers values
func NewUpdateMFAMethodForbidden() *UpdateMFAMethodForbidden {
	return &UpdateMFAMethodForbidden{}
}

/* UpdateMFAMethodForbidden describes a response with status code 403, with default header values.

HttpError
*/
type UpdateMFAMethodForbidden struct {
	Payload *models.Error
}

func (o *UpdateMFAMethodForbidden) Error() string {
	return fmt.Sprintf("[PUT /api/admin/{tid}/mfa-methods/{mfaID}][%d] updateMFAMethodForbidden  %+v", 403, o.Payload)
}
func (o *UpdateMFAMethodForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateMFAMethodForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateMFAMethodNotFound creates a UpdateMFAMethodNotFound with default headers values
func NewUpdateMFAMethodNotFound() *UpdateMFAMethodNotFound {
	return &UpdateMFAMethodNotFound{}
}

/* UpdateMFAMethodNotFound describes a response with status code 404, with default header values.

HttpError
*/
type UpdateMFAMethodNotFound struct {
	Payload *models.Error
}

func (o *UpdateMFAMethodNotFound) Error() string {
	return fmt.Sprintf("[PUT /api/admin/{tid}/mfa-methods/{mfaID}][%d] updateMFAMethodNotFound  %+v", 404, o.Payload)
}
func (o *UpdateMFAMethodNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateMFAMethodNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateMFAMethodConflict creates a UpdateMFAMethodConflict with default headers values
func NewUpdateMFAMethodConflict() *UpdateMFAMethodConflict {
	return &UpdateMFAMethodConflict{}
}

/* UpdateMFAMethodConflict describes a response with status code 409, with default header values.

HttpError
*/
type UpdateMFAMethodConflict struct {
	Payload *models.Error
}

func (o *UpdateMFAMethodConflict) Error() string {
	return fmt.Sprintf("[PUT /api/admin/{tid}/mfa-methods/{mfaID}][%d] updateMFAMethodConflict  %+v", 409, o.Payload)
}
func (o *UpdateMFAMethodConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateMFAMethodConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateMFAMethodUnprocessableEntity creates a UpdateMFAMethodUnprocessableEntity with default headers values
func NewUpdateMFAMethodUnprocessableEntity() *UpdateMFAMethodUnprocessableEntity {
	return &UpdateMFAMethodUnprocessableEntity{}
}

/* UpdateMFAMethodUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type UpdateMFAMethodUnprocessableEntity struct {
	Payload *models.Error
}

func (o *UpdateMFAMethodUnprocessableEntity) Error() string {
	return fmt.Sprintf("[PUT /api/admin/{tid}/mfa-methods/{mfaID}][%d] updateMFAMethodUnprocessableEntity  %+v", 422, o.Payload)
}
func (o *UpdateMFAMethodUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateMFAMethodUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
