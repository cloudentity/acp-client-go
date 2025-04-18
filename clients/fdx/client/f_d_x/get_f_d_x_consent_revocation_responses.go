// Code generated by go-swagger; DO NOT EDIT.

package f_d_x

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/fdx/models"
)

// GetFDXConsentRevocationReader is a Reader for the GetFDXConsentRevocation structure.
type GetFDXConsentRevocationReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetFDXConsentRevocationReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetFDXConsentRevocationOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetFDXConsentRevocationBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetFDXConsentRevocationUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetFDXConsentRevocationNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /consents/{consentID}/revocation] getFDXConsentRevocation", response, response.Code())
	}
}

// NewGetFDXConsentRevocationOK creates a GetFDXConsentRevocationOK with default headers values
func NewGetFDXConsentRevocationOK() *GetFDXConsentRevocationOK {
	return &GetFDXConsentRevocationOK{}
}

/*
GetFDXConsentRevocationOK describes a response with status code 200, with default header values.

GetFDXConsentRevocation
*/
type GetFDXConsentRevocationOK struct {
	Payload *models.GetFDXConsentRevocation
}

// IsSuccess returns true when this get f d x consent revocation o k response has a 2xx status code
func (o *GetFDXConsentRevocationOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get f d x consent revocation o k response has a 3xx status code
func (o *GetFDXConsentRevocationOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get f d x consent revocation o k response has a 4xx status code
func (o *GetFDXConsentRevocationOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get f d x consent revocation o k response has a 5xx status code
func (o *GetFDXConsentRevocationOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get f d x consent revocation o k response a status code equal to that given
func (o *GetFDXConsentRevocationOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get f d x consent revocation o k response
func (o *GetFDXConsentRevocationOK) Code() int {
	return 200
}

func (o *GetFDXConsentRevocationOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /consents/{consentID}/revocation][%d] getFDXConsentRevocationOK %s", 200, payload)
}

func (o *GetFDXConsentRevocationOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /consents/{consentID}/revocation][%d] getFDXConsentRevocationOK %s", 200, payload)
}

func (o *GetFDXConsentRevocationOK) GetPayload() *models.GetFDXConsentRevocation {
	return o.Payload
}

func (o *GetFDXConsentRevocationOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GetFDXConsentRevocation)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetFDXConsentRevocationBadRequest creates a GetFDXConsentRevocationBadRequest with default headers values
func NewGetFDXConsentRevocationBadRequest() *GetFDXConsentRevocationBadRequest {
	return &GetFDXConsentRevocationBadRequest{}
}

/*
GetFDXConsentRevocationBadRequest describes a response with status code 400, with default header values.

FDX Error
*/
type GetFDXConsentRevocationBadRequest struct {
	Payload *models.FDXErrorResponse
}

// IsSuccess returns true when this get f d x consent revocation bad request response has a 2xx status code
func (o *GetFDXConsentRevocationBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get f d x consent revocation bad request response has a 3xx status code
func (o *GetFDXConsentRevocationBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get f d x consent revocation bad request response has a 4xx status code
func (o *GetFDXConsentRevocationBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get f d x consent revocation bad request response has a 5xx status code
func (o *GetFDXConsentRevocationBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get f d x consent revocation bad request response a status code equal to that given
func (o *GetFDXConsentRevocationBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get f d x consent revocation bad request response
func (o *GetFDXConsentRevocationBadRequest) Code() int {
	return 400
}

func (o *GetFDXConsentRevocationBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /consents/{consentID}/revocation][%d] getFDXConsentRevocationBadRequest %s", 400, payload)
}

func (o *GetFDXConsentRevocationBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /consents/{consentID}/revocation][%d] getFDXConsentRevocationBadRequest %s", 400, payload)
}

func (o *GetFDXConsentRevocationBadRequest) GetPayload() *models.FDXErrorResponse {
	return o.Payload
}

func (o *GetFDXConsentRevocationBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.FDXErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetFDXConsentRevocationUnauthorized creates a GetFDXConsentRevocationUnauthorized with default headers values
func NewGetFDXConsentRevocationUnauthorized() *GetFDXConsentRevocationUnauthorized {
	return &GetFDXConsentRevocationUnauthorized{}
}

/*
GetFDXConsentRevocationUnauthorized describes a response with status code 401, with default header values.

FDX Error
*/
type GetFDXConsentRevocationUnauthorized struct {
	Payload *models.FDXErrorResponse
}

// IsSuccess returns true when this get f d x consent revocation unauthorized response has a 2xx status code
func (o *GetFDXConsentRevocationUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get f d x consent revocation unauthorized response has a 3xx status code
func (o *GetFDXConsentRevocationUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get f d x consent revocation unauthorized response has a 4xx status code
func (o *GetFDXConsentRevocationUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get f d x consent revocation unauthorized response has a 5xx status code
func (o *GetFDXConsentRevocationUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get f d x consent revocation unauthorized response a status code equal to that given
func (o *GetFDXConsentRevocationUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get f d x consent revocation unauthorized response
func (o *GetFDXConsentRevocationUnauthorized) Code() int {
	return 401
}

func (o *GetFDXConsentRevocationUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /consents/{consentID}/revocation][%d] getFDXConsentRevocationUnauthorized %s", 401, payload)
}

func (o *GetFDXConsentRevocationUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /consents/{consentID}/revocation][%d] getFDXConsentRevocationUnauthorized %s", 401, payload)
}

func (o *GetFDXConsentRevocationUnauthorized) GetPayload() *models.FDXErrorResponse {
	return o.Payload
}

func (o *GetFDXConsentRevocationUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.FDXErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetFDXConsentRevocationNotFound creates a GetFDXConsentRevocationNotFound with default headers values
func NewGetFDXConsentRevocationNotFound() *GetFDXConsentRevocationNotFound {
	return &GetFDXConsentRevocationNotFound{}
}

/*
GetFDXConsentRevocationNotFound describes a response with status code 404, with default header values.

FDX Error
*/
type GetFDXConsentRevocationNotFound struct {
	Payload *models.FDXErrorResponse
}

// IsSuccess returns true when this get f d x consent revocation not found response has a 2xx status code
func (o *GetFDXConsentRevocationNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get f d x consent revocation not found response has a 3xx status code
func (o *GetFDXConsentRevocationNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get f d x consent revocation not found response has a 4xx status code
func (o *GetFDXConsentRevocationNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get f d x consent revocation not found response has a 5xx status code
func (o *GetFDXConsentRevocationNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get f d x consent revocation not found response a status code equal to that given
func (o *GetFDXConsentRevocationNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get f d x consent revocation not found response
func (o *GetFDXConsentRevocationNotFound) Code() int {
	return 404
}

func (o *GetFDXConsentRevocationNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /consents/{consentID}/revocation][%d] getFDXConsentRevocationNotFound %s", 404, payload)
}

func (o *GetFDXConsentRevocationNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /consents/{consentID}/revocation][%d] getFDXConsentRevocationNotFound %s", 404, payload)
}

func (o *GetFDXConsentRevocationNotFound) GetPayload() *models.FDXErrorResponse {
	return o.Payload
}

func (o *GetFDXConsentRevocationNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.FDXErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
