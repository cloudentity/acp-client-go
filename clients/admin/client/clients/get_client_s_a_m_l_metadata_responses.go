// Code generated by go-swagger; DO NOT EDIT.

package clients

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// GetClientSAMLMetadataReader is a Reader for the GetClientSAMLMetadata structure.
type GetClientSAMLMetadataReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetClientSAMLMetadataReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetClientSAMLMetadataOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetClientSAMLMetadataUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetClientSAMLMetadataForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetClientSAMLMetadataNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetClientSAMLMetadataTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetClientSAMLMetadataOK creates a GetClientSAMLMetadataOK with default headers values
func NewGetClientSAMLMetadataOK() *GetClientSAMLMetadataOK {
	return &GetClientSAMLMetadataOK{}
}

/*
GetClientSAMLMetadataOK describes a response with status code 200, with default header values.

SAML Client metadata
*/
type GetClientSAMLMetadataOK struct {
	Payload *models.SAMLClientMetadataResponse
}

// IsSuccess returns true when this get client s a m l metadata o k response has a 2xx status code
func (o *GetClientSAMLMetadataOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get client s a m l metadata o k response has a 3xx status code
func (o *GetClientSAMLMetadataOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get client s a m l metadata o k response has a 4xx status code
func (o *GetClientSAMLMetadataOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get client s a m l metadata o k response has a 5xx status code
func (o *GetClientSAMLMetadataOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get client s a m l metadata o k response a status code equal to that given
func (o *GetClientSAMLMetadataOK) IsCode(code int) bool {
	return code == 200
}

func (o *GetClientSAMLMetadataOK) Error() string {
	return fmt.Sprintf("[GET /clients/{cid}/saml/metadata][%d] getClientSAMLMetadataOK  %+v", 200, o.Payload)
}

func (o *GetClientSAMLMetadataOK) String() string {
	return fmt.Sprintf("[GET /clients/{cid}/saml/metadata][%d] getClientSAMLMetadataOK  %+v", 200, o.Payload)
}

func (o *GetClientSAMLMetadataOK) GetPayload() *models.SAMLClientMetadataResponse {
	return o.Payload
}

func (o *GetClientSAMLMetadataOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.SAMLClientMetadataResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetClientSAMLMetadataUnauthorized creates a GetClientSAMLMetadataUnauthorized with default headers values
func NewGetClientSAMLMetadataUnauthorized() *GetClientSAMLMetadataUnauthorized {
	return &GetClientSAMLMetadataUnauthorized{}
}

/*
GetClientSAMLMetadataUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type GetClientSAMLMetadataUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get client s a m l metadata unauthorized response has a 2xx status code
func (o *GetClientSAMLMetadataUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get client s a m l metadata unauthorized response has a 3xx status code
func (o *GetClientSAMLMetadataUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get client s a m l metadata unauthorized response has a 4xx status code
func (o *GetClientSAMLMetadataUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get client s a m l metadata unauthorized response has a 5xx status code
func (o *GetClientSAMLMetadataUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get client s a m l metadata unauthorized response a status code equal to that given
func (o *GetClientSAMLMetadataUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *GetClientSAMLMetadataUnauthorized) Error() string {
	return fmt.Sprintf("[GET /clients/{cid}/saml/metadata][%d] getClientSAMLMetadataUnauthorized  %+v", 401, o.Payload)
}

func (o *GetClientSAMLMetadataUnauthorized) String() string {
	return fmt.Sprintf("[GET /clients/{cid}/saml/metadata][%d] getClientSAMLMetadataUnauthorized  %+v", 401, o.Payload)
}

func (o *GetClientSAMLMetadataUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetClientSAMLMetadataUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetClientSAMLMetadataForbidden creates a GetClientSAMLMetadataForbidden with default headers values
func NewGetClientSAMLMetadataForbidden() *GetClientSAMLMetadataForbidden {
	return &GetClientSAMLMetadataForbidden{}
}

/*
GetClientSAMLMetadataForbidden describes a response with status code 403, with default header values.

HttpError
*/
type GetClientSAMLMetadataForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get client s a m l metadata forbidden response has a 2xx status code
func (o *GetClientSAMLMetadataForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get client s a m l metadata forbidden response has a 3xx status code
func (o *GetClientSAMLMetadataForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get client s a m l metadata forbidden response has a 4xx status code
func (o *GetClientSAMLMetadataForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get client s a m l metadata forbidden response has a 5xx status code
func (o *GetClientSAMLMetadataForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get client s a m l metadata forbidden response a status code equal to that given
func (o *GetClientSAMLMetadataForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *GetClientSAMLMetadataForbidden) Error() string {
	return fmt.Sprintf("[GET /clients/{cid}/saml/metadata][%d] getClientSAMLMetadataForbidden  %+v", 403, o.Payload)
}

func (o *GetClientSAMLMetadataForbidden) String() string {
	return fmt.Sprintf("[GET /clients/{cid}/saml/metadata][%d] getClientSAMLMetadataForbidden  %+v", 403, o.Payload)
}

func (o *GetClientSAMLMetadataForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetClientSAMLMetadataForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetClientSAMLMetadataNotFound creates a GetClientSAMLMetadataNotFound with default headers values
func NewGetClientSAMLMetadataNotFound() *GetClientSAMLMetadataNotFound {
	return &GetClientSAMLMetadataNotFound{}
}

/*
GetClientSAMLMetadataNotFound describes a response with status code 404, with default header values.

HttpError
*/
type GetClientSAMLMetadataNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get client s a m l metadata not found response has a 2xx status code
func (o *GetClientSAMLMetadataNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get client s a m l metadata not found response has a 3xx status code
func (o *GetClientSAMLMetadataNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get client s a m l metadata not found response has a 4xx status code
func (o *GetClientSAMLMetadataNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get client s a m l metadata not found response has a 5xx status code
func (o *GetClientSAMLMetadataNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get client s a m l metadata not found response a status code equal to that given
func (o *GetClientSAMLMetadataNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *GetClientSAMLMetadataNotFound) Error() string {
	return fmt.Sprintf("[GET /clients/{cid}/saml/metadata][%d] getClientSAMLMetadataNotFound  %+v", 404, o.Payload)
}

func (o *GetClientSAMLMetadataNotFound) String() string {
	return fmt.Sprintf("[GET /clients/{cid}/saml/metadata][%d] getClientSAMLMetadataNotFound  %+v", 404, o.Payload)
}

func (o *GetClientSAMLMetadataNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetClientSAMLMetadataNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetClientSAMLMetadataTooManyRequests creates a GetClientSAMLMetadataTooManyRequests with default headers values
func NewGetClientSAMLMetadataTooManyRequests() *GetClientSAMLMetadataTooManyRequests {
	return &GetClientSAMLMetadataTooManyRequests{}
}

/*
GetClientSAMLMetadataTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type GetClientSAMLMetadataTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get client s a m l metadata too many requests response has a 2xx status code
func (o *GetClientSAMLMetadataTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get client s a m l metadata too many requests response has a 3xx status code
func (o *GetClientSAMLMetadataTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get client s a m l metadata too many requests response has a 4xx status code
func (o *GetClientSAMLMetadataTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get client s a m l metadata too many requests response has a 5xx status code
func (o *GetClientSAMLMetadataTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get client s a m l metadata too many requests response a status code equal to that given
func (o *GetClientSAMLMetadataTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *GetClientSAMLMetadataTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /clients/{cid}/saml/metadata][%d] getClientSAMLMetadataTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetClientSAMLMetadataTooManyRequests) String() string {
	return fmt.Sprintf("[GET /clients/{cid}/saml/metadata][%d] getClientSAMLMetadataTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetClientSAMLMetadataTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetClientSAMLMetadataTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
