// Code generated by go-swagger; DO NOT EDIT.

package idps

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/models"
)

// GetOIDCIDPReader is a Reader for the GetOIDCIDP structure.
type GetOIDCIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetOIDCIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetOIDCIDPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetOIDCIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetOIDCIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetOIDCIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetOIDCIDPOK creates a GetOIDCIDPOK with default headers values
func NewGetOIDCIDPOK() *GetOIDCIDPOK {
	return &GetOIDCIDPOK{}
}

/* GetOIDCIDPOK describes a response with status code 200, with default header values.

OIDCIDP
*/
type GetOIDCIDPOK struct {
	Payload *models.OIDCIDP
}

func (o *GetOIDCIDPOK) Error() string {
	return fmt.Sprintf("[GET /api/admin/{tid}/servers/{aid}/idps/oidc/{iid}][%d] getOIdCIdPOK  %+v", 200, o.Payload)
}
func (o *GetOIDCIDPOK) GetPayload() *models.OIDCIDP {
	return o.Payload
}

func (o *GetOIDCIDPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OIDCIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOIDCIDPUnauthorized creates a GetOIDCIDPUnauthorized with default headers values
func NewGetOIDCIDPUnauthorized() *GetOIDCIDPUnauthorized {
	return &GetOIDCIDPUnauthorized{}
}

/* GetOIDCIDPUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type GetOIDCIDPUnauthorized struct {
	Payload *models.Error
}

func (o *GetOIDCIDPUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/admin/{tid}/servers/{aid}/idps/oidc/{iid}][%d] getOIdCIdPUnauthorized  %+v", 401, o.Payload)
}
func (o *GetOIDCIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOIDCIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOIDCIDPForbidden creates a GetOIDCIDPForbidden with default headers values
func NewGetOIDCIDPForbidden() *GetOIDCIDPForbidden {
	return &GetOIDCIDPForbidden{}
}

/* GetOIDCIDPForbidden describes a response with status code 403, with default header values.

HttpError
*/
type GetOIDCIDPForbidden struct {
	Payload *models.Error
}

func (o *GetOIDCIDPForbidden) Error() string {
	return fmt.Sprintf("[GET /api/admin/{tid}/servers/{aid}/idps/oidc/{iid}][%d] getOIdCIdPForbidden  %+v", 403, o.Payload)
}
func (o *GetOIDCIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOIDCIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOIDCIDPNotFound creates a GetOIDCIDPNotFound with default headers values
func NewGetOIDCIDPNotFound() *GetOIDCIDPNotFound {
	return &GetOIDCIDPNotFound{}
}

/* GetOIDCIDPNotFound describes a response with status code 404, with default header values.

HttpError
*/
type GetOIDCIDPNotFound struct {
	Payload *models.Error
}

func (o *GetOIDCIDPNotFound) Error() string {
	return fmt.Sprintf("[GET /api/admin/{tid}/servers/{aid}/idps/oidc/{iid}][%d] getOIdCIdPNotFound  %+v", 404, o.Payload)
}
func (o *GetOIDCIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOIDCIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
