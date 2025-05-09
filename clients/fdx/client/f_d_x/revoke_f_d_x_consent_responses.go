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

// RevokeFDXConsentReader is a Reader for the RevokeFDXConsent structure.
type RevokeFDXConsentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RevokeFDXConsentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewRevokeFDXConsentNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewRevokeFDXConsentBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewRevokeFDXConsentUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRevokeFDXConsentForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRevokeFDXConsentNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewRevokeFDXConsentConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PUT /consents/{consentID}/revocation] revokeFDXConsent", response, response.Code())
	}
}

// NewRevokeFDXConsentNoContent creates a RevokeFDXConsentNoContent with default headers values
func NewRevokeFDXConsentNoContent() *RevokeFDXConsentNoContent {
	return &RevokeFDXConsentNoContent{}
}

/*
RevokeFDXConsentNoContent describes a response with status code 204, with default header values.

	FDX Consent Revoked
*/
type RevokeFDXConsentNoContent struct {
}

// IsSuccess returns true when this revoke f d x consent no content response has a 2xx status code
func (o *RevokeFDXConsentNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this revoke f d x consent no content response has a 3xx status code
func (o *RevokeFDXConsentNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke f d x consent no content response has a 4xx status code
func (o *RevokeFDXConsentNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this revoke f d x consent no content response has a 5xx status code
func (o *RevokeFDXConsentNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke f d x consent no content response a status code equal to that given
func (o *RevokeFDXConsentNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the revoke f d x consent no content response
func (o *RevokeFDXConsentNoContent) Code() int {
	return 204
}

func (o *RevokeFDXConsentNoContent) Error() string {
	return fmt.Sprintf("[PUT /consents/{consentID}/revocation][%d] revokeFDXConsentNoContent", 204)
}

func (o *RevokeFDXConsentNoContent) String() string {
	return fmt.Sprintf("[PUT /consents/{consentID}/revocation][%d] revokeFDXConsentNoContent", 204)
}

func (o *RevokeFDXConsentNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewRevokeFDXConsentBadRequest creates a RevokeFDXConsentBadRequest with default headers values
func NewRevokeFDXConsentBadRequest() *RevokeFDXConsentBadRequest {
	return &RevokeFDXConsentBadRequest{}
}

/*
RevokeFDXConsentBadRequest describes a response with status code 400, with default header values.

FDX Error
*/
type RevokeFDXConsentBadRequest struct {
	Payload *models.FDXErrorResponse
}

// IsSuccess returns true when this revoke f d x consent bad request response has a 2xx status code
func (o *RevokeFDXConsentBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke f d x consent bad request response has a 3xx status code
func (o *RevokeFDXConsentBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke f d x consent bad request response has a 4xx status code
func (o *RevokeFDXConsentBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke f d x consent bad request response has a 5xx status code
func (o *RevokeFDXConsentBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke f d x consent bad request response a status code equal to that given
func (o *RevokeFDXConsentBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the revoke f d x consent bad request response
func (o *RevokeFDXConsentBadRequest) Code() int {
	return 400
}

func (o *RevokeFDXConsentBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /consents/{consentID}/revocation][%d] revokeFDXConsentBadRequest %s", 400, payload)
}

func (o *RevokeFDXConsentBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /consents/{consentID}/revocation][%d] revokeFDXConsentBadRequest %s", 400, payload)
}

func (o *RevokeFDXConsentBadRequest) GetPayload() *models.FDXErrorResponse {
	return o.Payload
}

func (o *RevokeFDXConsentBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.FDXErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeFDXConsentUnauthorized creates a RevokeFDXConsentUnauthorized with default headers values
func NewRevokeFDXConsentUnauthorized() *RevokeFDXConsentUnauthorized {
	return &RevokeFDXConsentUnauthorized{}
}

/*
RevokeFDXConsentUnauthorized describes a response with status code 401, with default header values.

FDX Error
*/
type RevokeFDXConsentUnauthorized struct {
	Payload *models.FDXErrorResponse
}

// IsSuccess returns true when this revoke f d x consent unauthorized response has a 2xx status code
func (o *RevokeFDXConsentUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke f d x consent unauthorized response has a 3xx status code
func (o *RevokeFDXConsentUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke f d x consent unauthorized response has a 4xx status code
func (o *RevokeFDXConsentUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke f d x consent unauthorized response has a 5xx status code
func (o *RevokeFDXConsentUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke f d x consent unauthorized response a status code equal to that given
func (o *RevokeFDXConsentUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the revoke f d x consent unauthorized response
func (o *RevokeFDXConsentUnauthorized) Code() int {
	return 401
}

func (o *RevokeFDXConsentUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /consents/{consentID}/revocation][%d] revokeFDXConsentUnauthorized %s", 401, payload)
}

func (o *RevokeFDXConsentUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /consents/{consentID}/revocation][%d] revokeFDXConsentUnauthorized %s", 401, payload)
}

func (o *RevokeFDXConsentUnauthorized) GetPayload() *models.FDXErrorResponse {
	return o.Payload
}

func (o *RevokeFDXConsentUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.FDXErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeFDXConsentForbidden creates a RevokeFDXConsentForbidden with default headers values
func NewRevokeFDXConsentForbidden() *RevokeFDXConsentForbidden {
	return &RevokeFDXConsentForbidden{}
}

/*
RevokeFDXConsentForbidden describes a response with status code 403, with default header values.

FDX Error
*/
type RevokeFDXConsentForbidden struct {
	Payload *models.FDXErrorResponse
}

// IsSuccess returns true when this revoke f d x consent forbidden response has a 2xx status code
func (o *RevokeFDXConsentForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke f d x consent forbidden response has a 3xx status code
func (o *RevokeFDXConsentForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke f d x consent forbidden response has a 4xx status code
func (o *RevokeFDXConsentForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke f d x consent forbidden response has a 5xx status code
func (o *RevokeFDXConsentForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke f d x consent forbidden response a status code equal to that given
func (o *RevokeFDXConsentForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the revoke f d x consent forbidden response
func (o *RevokeFDXConsentForbidden) Code() int {
	return 403
}

func (o *RevokeFDXConsentForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /consents/{consentID}/revocation][%d] revokeFDXConsentForbidden %s", 403, payload)
}

func (o *RevokeFDXConsentForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /consents/{consentID}/revocation][%d] revokeFDXConsentForbidden %s", 403, payload)
}

func (o *RevokeFDXConsentForbidden) GetPayload() *models.FDXErrorResponse {
	return o.Payload
}

func (o *RevokeFDXConsentForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.FDXErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeFDXConsentNotFound creates a RevokeFDXConsentNotFound with default headers values
func NewRevokeFDXConsentNotFound() *RevokeFDXConsentNotFound {
	return &RevokeFDXConsentNotFound{}
}

/*
RevokeFDXConsentNotFound describes a response with status code 404, with default header values.

FDX Error
*/
type RevokeFDXConsentNotFound struct {
	Payload *models.FDXErrorResponse
}

// IsSuccess returns true when this revoke f d x consent not found response has a 2xx status code
func (o *RevokeFDXConsentNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke f d x consent not found response has a 3xx status code
func (o *RevokeFDXConsentNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke f d x consent not found response has a 4xx status code
func (o *RevokeFDXConsentNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke f d x consent not found response has a 5xx status code
func (o *RevokeFDXConsentNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke f d x consent not found response a status code equal to that given
func (o *RevokeFDXConsentNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the revoke f d x consent not found response
func (o *RevokeFDXConsentNotFound) Code() int {
	return 404
}

func (o *RevokeFDXConsentNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /consents/{consentID}/revocation][%d] revokeFDXConsentNotFound %s", 404, payload)
}

func (o *RevokeFDXConsentNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /consents/{consentID}/revocation][%d] revokeFDXConsentNotFound %s", 404, payload)
}

func (o *RevokeFDXConsentNotFound) GetPayload() *models.FDXErrorResponse {
	return o.Payload
}

func (o *RevokeFDXConsentNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.FDXErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeFDXConsentConflict creates a RevokeFDXConsentConflict with default headers values
func NewRevokeFDXConsentConflict() *RevokeFDXConsentConflict {
	return &RevokeFDXConsentConflict{}
}

/*
RevokeFDXConsentConflict describes a response with status code 409, with default header values.

FDX Error
*/
type RevokeFDXConsentConflict struct {
	Payload *models.FDXErrorResponse
}

// IsSuccess returns true when this revoke f d x consent conflict response has a 2xx status code
func (o *RevokeFDXConsentConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke f d x consent conflict response has a 3xx status code
func (o *RevokeFDXConsentConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke f d x consent conflict response has a 4xx status code
func (o *RevokeFDXConsentConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke f d x consent conflict response has a 5xx status code
func (o *RevokeFDXConsentConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke f d x consent conflict response a status code equal to that given
func (o *RevokeFDXConsentConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the revoke f d x consent conflict response
func (o *RevokeFDXConsentConflict) Code() int {
	return 409
}

func (o *RevokeFDXConsentConflict) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /consents/{consentID}/revocation][%d] revokeFDXConsentConflict %s", 409, payload)
}

func (o *RevokeFDXConsentConflict) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /consents/{consentID}/revocation][%d] revokeFDXConsentConflict %s", 409, payload)
}

func (o *RevokeFDXConsentConflict) GetPayload() *models.FDXErrorResponse {
	return o.Payload
}

func (o *RevokeFDXConsentConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.FDXErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
