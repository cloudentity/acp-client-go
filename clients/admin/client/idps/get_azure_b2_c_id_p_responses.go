// Code generated by go-swagger; DO NOT EDIT.

package idps

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// GetAzureB2CIDPReader is a Reader for the GetAzureB2CIDP structure.
type GetAzureB2CIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAzureB2CIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAzureB2CIDPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetAzureB2CIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetAzureB2CIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetAzureB2CIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetAzureB2CIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetAzureB2CIDPOK creates a GetAzureB2CIDPOK with default headers values
func NewGetAzureB2CIDPOK() *GetAzureB2CIDPOK {
	return &GetAzureB2CIDPOK{}
}

/* GetAzureB2CIDPOK describes a response with status code 200, with default header values.

AzureB2CIDP
*/
type GetAzureB2CIDPOK struct {
	Payload *models.AzureB2CIDP
}

func (o *GetAzureB2CIDPOK) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/azureb2c/{iid}][%d] getAzureB2CIdPOK  %+v", 200, o.Payload)
}
func (o *GetAzureB2CIDPOK) GetPayload() *models.AzureB2CIDP {
	return o.Payload
}

func (o *GetAzureB2CIDPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.AzureB2CIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAzureB2CIDPUnauthorized creates a GetAzureB2CIDPUnauthorized with default headers values
func NewGetAzureB2CIDPUnauthorized() *GetAzureB2CIDPUnauthorized {
	return &GetAzureB2CIDPUnauthorized{}
}

/* GetAzureB2CIDPUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type GetAzureB2CIDPUnauthorized struct {
	Payload *models.Error
}

func (o *GetAzureB2CIDPUnauthorized) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/azureb2c/{iid}][%d] getAzureB2CIdPUnauthorized  %+v", 401, o.Payload)
}
func (o *GetAzureB2CIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAzureB2CIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAzureB2CIDPForbidden creates a GetAzureB2CIDPForbidden with default headers values
func NewGetAzureB2CIDPForbidden() *GetAzureB2CIDPForbidden {
	return &GetAzureB2CIDPForbidden{}
}

/* GetAzureB2CIDPForbidden describes a response with status code 403, with default header values.

HttpError
*/
type GetAzureB2CIDPForbidden struct {
	Payload *models.Error
}

func (o *GetAzureB2CIDPForbidden) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/azureb2c/{iid}][%d] getAzureB2CIdPForbidden  %+v", 403, o.Payload)
}
func (o *GetAzureB2CIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAzureB2CIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAzureB2CIDPNotFound creates a GetAzureB2CIDPNotFound with default headers values
func NewGetAzureB2CIDPNotFound() *GetAzureB2CIDPNotFound {
	return &GetAzureB2CIDPNotFound{}
}

/* GetAzureB2CIDPNotFound describes a response with status code 404, with default header values.

HttpError
*/
type GetAzureB2CIDPNotFound struct {
	Payload *models.Error
}

func (o *GetAzureB2CIDPNotFound) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/azureb2c/{iid}][%d] getAzureB2CIdPNotFound  %+v", 404, o.Payload)
}
func (o *GetAzureB2CIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAzureB2CIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAzureB2CIDPTooManyRequests creates a GetAzureB2CIDPTooManyRequests with default headers values
func NewGetAzureB2CIDPTooManyRequests() *GetAzureB2CIDPTooManyRequests {
	return &GetAzureB2CIDPTooManyRequests{}
}

/* GetAzureB2CIDPTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type GetAzureB2CIDPTooManyRequests struct {
	Payload *models.Error
}

func (o *GetAzureB2CIDPTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/azureb2c/{iid}][%d] getAzureB2CIdPTooManyRequests  %+v", 429, o.Payload)
}
func (o *GetAzureB2CIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAzureB2CIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
