// Code generated by go-swagger; DO NOT EDIT.

package m_a_n_a_g_e_m_e_n_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/fdx/models"
)

// RevokeFDXConsentsReader is a Reader for the RevokeFDXConsents structure.
type RevokeFDXConsentsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RevokeFDXConsentsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRevokeFDXConsentsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewRevokeFDXConsentsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewRevokeFDXConsentsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRevokeFDXConsentsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRevokeFDXConsentsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRevokeFDXConsentsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewRevokeFDXConsentsOK creates a RevokeFDXConsentsOK with default headers values
func NewRevokeFDXConsentsOK() *RevokeFDXConsentsOK {
	return &RevokeFDXConsentsOK{}
}

/*
RevokeFDXConsentsOK describes a response with status code 200, with default header values.

ConsentsRemovedResponse
*/
type RevokeFDXConsentsOK struct {
	Payload *models.ConsentsRemovedResponse
}

// IsSuccess returns true when this revoke f d x consents o k response has a 2xx status code
func (o *RevokeFDXConsentsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this revoke f d x consents o k response has a 3xx status code
func (o *RevokeFDXConsentsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke f d x consents o k response has a 4xx status code
func (o *RevokeFDXConsentsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this revoke f d x consents o k response has a 5xx status code
func (o *RevokeFDXConsentsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke f d x consents o k response a status code equal to that given
func (o *RevokeFDXConsentsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the revoke f d x consents o k response
func (o *RevokeFDXConsentsOK) Code() int {
	return 200
}

func (o *RevokeFDXConsentsOK) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/fdx/consents][%d] revokeFDXConsentsOK  %+v", 200, o.Payload)
}

func (o *RevokeFDXConsentsOK) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/fdx/consents][%d] revokeFDXConsentsOK  %+v", 200, o.Payload)
}

func (o *RevokeFDXConsentsOK) GetPayload() *models.ConsentsRemovedResponse {
	return o.Payload
}

func (o *RevokeFDXConsentsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ConsentsRemovedResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeFDXConsentsBadRequest creates a RevokeFDXConsentsBadRequest with default headers values
func NewRevokeFDXConsentsBadRequest() *RevokeFDXConsentsBadRequest {
	return &RevokeFDXConsentsBadRequest{}
}

/*
RevokeFDXConsentsBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type RevokeFDXConsentsBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke f d x consents bad request response has a 2xx status code
func (o *RevokeFDXConsentsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke f d x consents bad request response has a 3xx status code
func (o *RevokeFDXConsentsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke f d x consents bad request response has a 4xx status code
func (o *RevokeFDXConsentsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke f d x consents bad request response has a 5xx status code
func (o *RevokeFDXConsentsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke f d x consents bad request response a status code equal to that given
func (o *RevokeFDXConsentsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the revoke f d x consents bad request response
func (o *RevokeFDXConsentsBadRequest) Code() int {
	return 400
}

func (o *RevokeFDXConsentsBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/fdx/consents][%d] revokeFDXConsentsBadRequest  %+v", 400, o.Payload)
}

func (o *RevokeFDXConsentsBadRequest) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/fdx/consents][%d] revokeFDXConsentsBadRequest  %+v", 400, o.Payload)
}

func (o *RevokeFDXConsentsBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeFDXConsentsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeFDXConsentsUnauthorized creates a RevokeFDXConsentsUnauthorized with default headers values
func NewRevokeFDXConsentsUnauthorized() *RevokeFDXConsentsUnauthorized {
	return &RevokeFDXConsentsUnauthorized{}
}

/*
RevokeFDXConsentsUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type RevokeFDXConsentsUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke f d x consents unauthorized response has a 2xx status code
func (o *RevokeFDXConsentsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke f d x consents unauthorized response has a 3xx status code
func (o *RevokeFDXConsentsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke f d x consents unauthorized response has a 4xx status code
func (o *RevokeFDXConsentsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke f d x consents unauthorized response has a 5xx status code
func (o *RevokeFDXConsentsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke f d x consents unauthorized response a status code equal to that given
func (o *RevokeFDXConsentsUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the revoke f d x consents unauthorized response
func (o *RevokeFDXConsentsUnauthorized) Code() int {
	return 401
}

func (o *RevokeFDXConsentsUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/fdx/consents][%d] revokeFDXConsentsUnauthorized  %+v", 401, o.Payload)
}

func (o *RevokeFDXConsentsUnauthorized) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/fdx/consents][%d] revokeFDXConsentsUnauthorized  %+v", 401, o.Payload)
}

func (o *RevokeFDXConsentsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeFDXConsentsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeFDXConsentsForbidden creates a RevokeFDXConsentsForbidden with default headers values
func NewRevokeFDXConsentsForbidden() *RevokeFDXConsentsForbidden {
	return &RevokeFDXConsentsForbidden{}
}

/*
RevokeFDXConsentsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type RevokeFDXConsentsForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke f d x consents forbidden response has a 2xx status code
func (o *RevokeFDXConsentsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke f d x consents forbidden response has a 3xx status code
func (o *RevokeFDXConsentsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke f d x consents forbidden response has a 4xx status code
func (o *RevokeFDXConsentsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke f d x consents forbidden response has a 5xx status code
func (o *RevokeFDXConsentsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke f d x consents forbidden response a status code equal to that given
func (o *RevokeFDXConsentsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the revoke f d x consents forbidden response
func (o *RevokeFDXConsentsForbidden) Code() int {
	return 403
}

func (o *RevokeFDXConsentsForbidden) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/fdx/consents][%d] revokeFDXConsentsForbidden  %+v", 403, o.Payload)
}

func (o *RevokeFDXConsentsForbidden) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/fdx/consents][%d] revokeFDXConsentsForbidden  %+v", 403, o.Payload)
}

func (o *RevokeFDXConsentsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeFDXConsentsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeFDXConsentsNotFound creates a RevokeFDXConsentsNotFound with default headers values
func NewRevokeFDXConsentsNotFound() *RevokeFDXConsentsNotFound {
	return &RevokeFDXConsentsNotFound{}
}

/*
RevokeFDXConsentsNotFound describes a response with status code 404, with default header values.

Not found
*/
type RevokeFDXConsentsNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke f d x consents not found response has a 2xx status code
func (o *RevokeFDXConsentsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke f d x consents not found response has a 3xx status code
func (o *RevokeFDXConsentsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke f d x consents not found response has a 4xx status code
func (o *RevokeFDXConsentsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke f d x consents not found response has a 5xx status code
func (o *RevokeFDXConsentsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke f d x consents not found response a status code equal to that given
func (o *RevokeFDXConsentsNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the revoke f d x consents not found response
func (o *RevokeFDXConsentsNotFound) Code() int {
	return 404
}

func (o *RevokeFDXConsentsNotFound) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/fdx/consents][%d] revokeFDXConsentsNotFound  %+v", 404, o.Payload)
}

func (o *RevokeFDXConsentsNotFound) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/fdx/consents][%d] revokeFDXConsentsNotFound  %+v", 404, o.Payload)
}

func (o *RevokeFDXConsentsNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeFDXConsentsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeFDXConsentsTooManyRequests creates a RevokeFDXConsentsTooManyRequests with default headers values
func NewRevokeFDXConsentsTooManyRequests() *RevokeFDXConsentsTooManyRequests {
	return &RevokeFDXConsentsTooManyRequests{}
}

/*
RevokeFDXConsentsTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type RevokeFDXConsentsTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke f d x consents too many requests response has a 2xx status code
func (o *RevokeFDXConsentsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke f d x consents too many requests response has a 3xx status code
func (o *RevokeFDXConsentsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke f d x consents too many requests response has a 4xx status code
func (o *RevokeFDXConsentsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke f d x consents too many requests response has a 5xx status code
func (o *RevokeFDXConsentsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke f d x consents too many requests response a status code equal to that given
func (o *RevokeFDXConsentsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the revoke f d x consents too many requests response
func (o *RevokeFDXConsentsTooManyRequests) Code() int {
	return 429
}

func (o *RevokeFDXConsentsTooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/fdx/consents][%d] revokeFDXConsentsTooManyRequests  %+v", 429, o.Payload)
}

func (o *RevokeFDXConsentsTooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/fdx/consents][%d] revokeFDXConsentsTooManyRequests  %+v", 429, o.Payload)
}

func (o *RevokeFDXConsentsTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeFDXConsentsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
