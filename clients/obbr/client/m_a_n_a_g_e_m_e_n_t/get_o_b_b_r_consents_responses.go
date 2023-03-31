// Code generated by go-swagger; DO NOT EDIT.

package m_a_n_a_g_e_m_e_n_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/obbr/models"
)

// GetOBBRConsentsReader is a Reader for the GetOBBRConsents structure.
type GetOBBRConsentsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetOBBRConsentsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetOBBRConsentsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetOBBRConsentsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetOBBRConsentsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetOBBRConsentsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetOBBRConsentsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetOBBRConsentsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetOBBRConsentsOK creates a GetOBBRConsentsOK with default headers values
func NewGetOBBRConsentsOK() *GetOBBRConsentsOK {
	return &GetOBBRConsentsOK{}
}

/*
GetOBBRConsentsOK describes a response with status code 200, with default header values.

OBBRConsents
*/
type GetOBBRConsentsOK struct {
	Payload *models.OBBRConsents
}

// IsSuccess returns true when this get o b b r consents o k response has a 2xx status code
func (o *GetOBBRConsentsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get o b b r consents o k response has a 3xx status code
func (o *GetOBBRConsentsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get o b b r consents o k response has a 4xx status code
func (o *GetOBBRConsentsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get o b b r consents o k response has a 5xx status code
func (o *GetOBBRConsentsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get o b b r consents o k response a status code equal to that given
func (o *GetOBBRConsentsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get o b b r consents o k response
func (o *GetOBBRConsentsOK) Code() int {
	return 200
}

func (o *GetOBBRConsentsOK) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/open-banking-brasil/consents][%d] getOBBRConsentsOK  %+v", 200, o.Payload)
}

func (o *GetOBBRConsentsOK) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/open-banking-brasil/consents][%d] getOBBRConsentsOK  %+v", 200, o.Payload)
}

func (o *GetOBBRConsentsOK) GetPayload() *models.OBBRConsents {
	return o.Payload
}

func (o *GetOBBRConsentsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRConsents)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOBBRConsentsBadRequest creates a GetOBBRConsentsBadRequest with default headers values
func NewGetOBBRConsentsBadRequest() *GetOBBRConsentsBadRequest {
	return &GetOBBRConsentsBadRequest{}
}

/*
GetOBBRConsentsBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type GetOBBRConsentsBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this get o b b r consents bad request response has a 2xx status code
func (o *GetOBBRConsentsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get o b b r consents bad request response has a 3xx status code
func (o *GetOBBRConsentsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get o b b r consents bad request response has a 4xx status code
func (o *GetOBBRConsentsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get o b b r consents bad request response has a 5xx status code
func (o *GetOBBRConsentsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get o b b r consents bad request response a status code equal to that given
func (o *GetOBBRConsentsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get o b b r consents bad request response
func (o *GetOBBRConsentsBadRequest) Code() int {
	return 400
}

func (o *GetOBBRConsentsBadRequest) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/open-banking-brasil/consents][%d] getOBBRConsentsBadRequest  %+v", 400, o.Payload)
}

func (o *GetOBBRConsentsBadRequest) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/open-banking-brasil/consents][%d] getOBBRConsentsBadRequest  %+v", 400, o.Payload)
}

func (o *GetOBBRConsentsBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOBBRConsentsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOBBRConsentsUnauthorized creates a GetOBBRConsentsUnauthorized with default headers values
func NewGetOBBRConsentsUnauthorized() *GetOBBRConsentsUnauthorized {
	return &GetOBBRConsentsUnauthorized{}
}

/*
GetOBBRConsentsUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetOBBRConsentsUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get o b b r consents unauthorized response has a 2xx status code
func (o *GetOBBRConsentsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get o b b r consents unauthorized response has a 3xx status code
func (o *GetOBBRConsentsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get o b b r consents unauthorized response has a 4xx status code
func (o *GetOBBRConsentsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get o b b r consents unauthorized response has a 5xx status code
func (o *GetOBBRConsentsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get o b b r consents unauthorized response a status code equal to that given
func (o *GetOBBRConsentsUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get o b b r consents unauthorized response
func (o *GetOBBRConsentsUnauthorized) Code() int {
	return 401
}

func (o *GetOBBRConsentsUnauthorized) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/open-banking-brasil/consents][%d] getOBBRConsentsUnauthorized  %+v", 401, o.Payload)
}

func (o *GetOBBRConsentsUnauthorized) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/open-banking-brasil/consents][%d] getOBBRConsentsUnauthorized  %+v", 401, o.Payload)
}

func (o *GetOBBRConsentsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOBBRConsentsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOBBRConsentsForbidden creates a GetOBBRConsentsForbidden with default headers values
func NewGetOBBRConsentsForbidden() *GetOBBRConsentsForbidden {
	return &GetOBBRConsentsForbidden{}
}

/*
GetOBBRConsentsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetOBBRConsentsForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get o b b r consents forbidden response has a 2xx status code
func (o *GetOBBRConsentsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get o b b r consents forbidden response has a 3xx status code
func (o *GetOBBRConsentsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get o b b r consents forbidden response has a 4xx status code
func (o *GetOBBRConsentsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get o b b r consents forbidden response has a 5xx status code
func (o *GetOBBRConsentsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get o b b r consents forbidden response a status code equal to that given
func (o *GetOBBRConsentsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get o b b r consents forbidden response
func (o *GetOBBRConsentsForbidden) Code() int {
	return 403
}

func (o *GetOBBRConsentsForbidden) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/open-banking-brasil/consents][%d] getOBBRConsentsForbidden  %+v", 403, o.Payload)
}

func (o *GetOBBRConsentsForbidden) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/open-banking-brasil/consents][%d] getOBBRConsentsForbidden  %+v", 403, o.Payload)
}

func (o *GetOBBRConsentsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOBBRConsentsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOBBRConsentsNotFound creates a GetOBBRConsentsNotFound with default headers values
func NewGetOBBRConsentsNotFound() *GetOBBRConsentsNotFound {
	return &GetOBBRConsentsNotFound{}
}

/*
GetOBBRConsentsNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetOBBRConsentsNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get o b b r consents not found response has a 2xx status code
func (o *GetOBBRConsentsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get o b b r consents not found response has a 3xx status code
func (o *GetOBBRConsentsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get o b b r consents not found response has a 4xx status code
func (o *GetOBBRConsentsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get o b b r consents not found response has a 5xx status code
func (o *GetOBBRConsentsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get o b b r consents not found response a status code equal to that given
func (o *GetOBBRConsentsNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get o b b r consents not found response
func (o *GetOBBRConsentsNotFound) Code() int {
	return 404
}

func (o *GetOBBRConsentsNotFound) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/open-banking-brasil/consents][%d] getOBBRConsentsNotFound  %+v", 404, o.Payload)
}

func (o *GetOBBRConsentsNotFound) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/open-banking-brasil/consents][%d] getOBBRConsentsNotFound  %+v", 404, o.Payload)
}

func (o *GetOBBRConsentsNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOBBRConsentsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOBBRConsentsTooManyRequests creates a GetOBBRConsentsTooManyRequests with default headers values
func NewGetOBBRConsentsTooManyRequests() *GetOBBRConsentsTooManyRequests {
	return &GetOBBRConsentsTooManyRequests{}
}

/*
GetOBBRConsentsTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetOBBRConsentsTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get o b b r consents too many requests response has a 2xx status code
func (o *GetOBBRConsentsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get o b b r consents too many requests response has a 3xx status code
func (o *GetOBBRConsentsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get o b b r consents too many requests response has a 4xx status code
func (o *GetOBBRConsentsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get o b b r consents too many requests response has a 5xx status code
func (o *GetOBBRConsentsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get o b b r consents too many requests response a status code equal to that given
func (o *GetOBBRConsentsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get o b b r consents too many requests response
func (o *GetOBBRConsentsTooManyRequests) Code() int {
	return 429
}

func (o *GetOBBRConsentsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/open-banking-brasil/consents][%d] getOBBRConsentsTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetOBBRConsentsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/open-banking-brasil/consents][%d] getOBBRConsentsTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetOBBRConsentsTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOBBRConsentsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
