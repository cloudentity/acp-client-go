// Code generated by go-swagger; DO NOT EDIT.

package vanity_domains

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// UpdateVanityDomainReader is a Reader for the UpdateVanityDomain structure.
type UpdateVanityDomainReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateVanityDomainReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateVanityDomainOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewUpdateVanityDomainUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdateVanityDomainForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateVanityDomainNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewUpdateVanityDomainConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewUpdateVanityDomainUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdateVanityDomainTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewUpdateVanityDomainOK creates a UpdateVanityDomainOK with default headers values
func NewUpdateVanityDomainOK() *UpdateVanityDomainOK {
	return &UpdateVanityDomainOK{}
}

/* UpdateVanityDomainOK describes a response with status code 200, with default header values.

Vanity domain
*/
type UpdateVanityDomainOK struct {
	Payload *models.VanityDomain
}

func (o *UpdateVanityDomainOK) Error() string {
	return fmt.Sprintf("[PUT /vanity-domains][%d] updateVanityDomainOK  %+v", 200, o.Payload)
}
func (o *UpdateVanityDomainOK) GetPayload() *models.VanityDomain {
	return o.Payload
}

func (o *UpdateVanityDomainOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.VanityDomain)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateVanityDomainUnauthorized creates a UpdateVanityDomainUnauthorized with default headers values
func NewUpdateVanityDomainUnauthorized() *UpdateVanityDomainUnauthorized {
	return &UpdateVanityDomainUnauthorized{}
}

/* UpdateVanityDomainUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type UpdateVanityDomainUnauthorized struct {
	Payload *models.Error
}

func (o *UpdateVanityDomainUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /vanity-domains][%d] updateVanityDomainUnauthorized  %+v", 401, o.Payload)
}
func (o *UpdateVanityDomainUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateVanityDomainUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateVanityDomainForbidden creates a UpdateVanityDomainForbidden with default headers values
func NewUpdateVanityDomainForbidden() *UpdateVanityDomainForbidden {
	return &UpdateVanityDomainForbidden{}
}

/* UpdateVanityDomainForbidden describes a response with status code 403, with default header values.

HttpError
*/
type UpdateVanityDomainForbidden struct {
	Payload *models.Error
}

func (o *UpdateVanityDomainForbidden) Error() string {
	return fmt.Sprintf("[PUT /vanity-domains][%d] updateVanityDomainForbidden  %+v", 403, o.Payload)
}
func (o *UpdateVanityDomainForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateVanityDomainForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateVanityDomainNotFound creates a UpdateVanityDomainNotFound with default headers values
func NewUpdateVanityDomainNotFound() *UpdateVanityDomainNotFound {
	return &UpdateVanityDomainNotFound{}
}

/* UpdateVanityDomainNotFound describes a response with status code 404, with default header values.

HttpError
*/
type UpdateVanityDomainNotFound struct {
	Payload *models.Error
}

func (o *UpdateVanityDomainNotFound) Error() string {
	return fmt.Sprintf("[PUT /vanity-domains][%d] updateVanityDomainNotFound  %+v", 404, o.Payload)
}
func (o *UpdateVanityDomainNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateVanityDomainNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateVanityDomainConflict creates a UpdateVanityDomainConflict with default headers values
func NewUpdateVanityDomainConflict() *UpdateVanityDomainConflict {
	return &UpdateVanityDomainConflict{}
}

/* UpdateVanityDomainConflict describes a response with status code 409, with default header values.

HttpError
*/
type UpdateVanityDomainConflict struct {
	Payload *models.Error
}

func (o *UpdateVanityDomainConflict) Error() string {
	return fmt.Sprintf("[PUT /vanity-domains][%d] updateVanityDomainConflict  %+v", 409, o.Payload)
}
func (o *UpdateVanityDomainConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateVanityDomainConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateVanityDomainUnprocessableEntity creates a UpdateVanityDomainUnprocessableEntity with default headers values
func NewUpdateVanityDomainUnprocessableEntity() *UpdateVanityDomainUnprocessableEntity {
	return &UpdateVanityDomainUnprocessableEntity{}
}

/* UpdateVanityDomainUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type UpdateVanityDomainUnprocessableEntity struct {
	Payload *models.Error
}

func (o *UpdateVanityDomainUnprocessableEntity) Error() string {
	return fmt.Sprintf("[PUT /vanity-domains][%d] updateVanityDomainUnprocessableEntity  %+v", 422, o.Payload)
}
func (o *UpdateVanityDomainUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateVanityDomainUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateVanityDomainTooManyRequests creates a UpdateVanityDomainTooManyRequests with default headers values
func NewUpdateVanityDomainTooManyRequests() *UpdateVanityDomainTooManyRequests {
	return &UpdateVanityDomainTooManyRequests{}
}

/* UpdateVanityDomainTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type UpdateVanityDomainTooManyRequests struct {
	Payload *models.Error
}

func (o *UpdateVanityDomainTooManyRequests) Error() string {
	return fmt.Sprintf("[PUT /vanity-domains][%d] updateVanityDomainTooManyRequests  %+v", 429, o.Payload)
}
func (o *UpdateVanityDomainTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateVanityDomainTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}