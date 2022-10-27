// Code generated by go-swagger; DO NOT EDIT.

package f_d_x

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/openbanking/models"
)

// RevokeFDXConsentByIDReader is a Reader for the RevokeFDXConsentByID structure.
type RevokeFDXConsentByIDReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RevokeFDXConsentByIDReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewRevokeFDXConsentByIDNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewRevokeFDXConsentByIDUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRevokeFDXConsentByIDForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRevokeFDXConsentByIDNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewRevokeFDXConsentByIDUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRevokeFDXConsentByIDTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewRevokeFDXConsentByIDNoContent creates a RevokeFDXConsentByIDNoContent with default headers values
func NewRevokeFDXConsentByIDNoContent() *RevokeFDXConsentByIDNoContent {
	return &RevokeFDXConsentByIDNoContent{}
}

/*
RevokeFDXConsentByIDNoContent describes a response with status code 204, with default header values.

	Consnet has been revoked
*/
type RevokeFDXConsentByIDNoContent struct {
}

// IsSuccess returns true when this revoke f d x consent by Id no content response has a 2xx status code
func (o *RevokeFDXConsentByIDNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this revoke f d x consent by Id no content response has a 3xx status code
func (o *RevokeFDXConsentByIDNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke f d x consent by Id no content response has a 4xx status code
func (o *RevokeFDXConsentByIDNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this revoke f d x consent by Id no content response has a 5xx status code
func (o *RevokeFDXConsentByIDNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke f d x consent by Id no content response a status code equal to that given
func (o *RevokeFDXConsentByIDNoContent) IsCode(code int) bool {
	return code == 204
}

func (o *RevokeFDXConsentByIDNoContent) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/fdx/consents/{consentID}][%d] revokeFDXConsentByIdNoContent ", 204)
}

func (o *RevokeFDXConsentByIDNoContent) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/fdx/consents/{consentID}][%d] revokeFDXConsentByIdNoContent ", 204)
}

func (o *RevokeFDXConsentByIDNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewRevokeFDXConsentByIDUnauthorized creates a RevokeFDXConsentByIDUnauthorized with default headers values
func NewRevokeFDXConsentByIDUnauthorized() *RevokeFDXConsentByIDUnauthorized {
	return &RevokeFDXConsentByIDUnauthorized{}
}

/*
RevokeFDXConsentByIDUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type RevokeFDXConsentByIDUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke f d x consent by Id unauthorized response has a 2xx status code
func (o *RevokeFDXConsentByIDUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke f d x consent by Id unauthorized response has a 3xx status code
func (o *RevokeFDXConsentByIDUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke f d x consent by Id unauthorized response has a 4xx status code
func (o *RevokeFDXConsentByIDUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke f d x consent by Id unauthorized response has a 5xx status code
func (o *RevokeFDXConsentByIDUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke f d x consent by Id unauthorized response a status code equal to that given
func (o *RevokeFDXConsentByIDUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *RevokeFDXConsentByIDUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/fdx/consents/{consentID}][%d] revokeFDXConsentByIdUnauthorized  %+v", 401, o.Payload)
}

func (o *RevokeFDXConsentByIDUnauthorized) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/fdx/consents/{consentID}][%d] revokeFDXConsentByIdUnauthorized  %+v", 401, o.Payload)
}

func (o *RevokeFDXConsentByIDUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeFDXConsentByIDUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeFDXConsentByIDForbidden creates a RevokeFDXConsentByIDForbidden with default headers values
func NewRevokeFDXConsentByIDForbidden() *RevokeFDXConsentByIDForbidden {
	return &RevokeFDXConsentByIDForbidden{}
}

/*
RevokeFDXConsentByIDForbidden describes a response with status code 403, with default header values.

HttpError
*/
type RevokeFDXConsentByIDForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke f d x consent by Id forbidden response has a 2xx status code
func (o *RevokeFDXConsentByIDForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke f d x consent by Id forbidden response has a 3xx status code
func (o *RevokeFDXConsentByIDForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke f d x consent by Id forbidden response has a 4xx status code
func (o *RevokeFDXConsentByIDForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke f d x consent by Id forbidden response has a 5xx status code
func (o *RevokeFDXConsentByIDForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke f d x consent by Id forbidden response a status code equal to that given
func (o *RevokeFDXConsentByIDForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *RevokeFDXConsentByIDForbidden) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/fdx/consents/{consentID}][%d] revokeFDXConsentByIdForbidden  %+v", 403, o.Payload)
}

func (o *RevokeFDXConsentByIDForbidden) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/fdx/consents/{consentID}][%d] revokeFDXConsentByIdForbidden  %+v", 403, o.Payload)
}

func (o *RevokeFDXConsentByIDForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeFDXConsentByIDForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeFDXConsentByIDNotFound creates a RevokeFDXConsentByIDNotFound with default headers values
func NewRevokeFDXConsentByIDNotFound() *RevokeFDXConsentByIDNotFound {
	return &RevokeFDXConsentByIDNotFound{}
}

/*
RevokeFDXConsentByIDNotFound describes a response with status code 404, with default header values.

HttpError
*/
type RevokeFDXConsentByIDNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke f d x consent by Id not found response has a 2xx status code
func (o *RevokeFDXConsentByIDNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke f d x consent by Id not found response has a 3xx status code
func (o *RevokeFDXConsentByIDNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke f d x consent by Id not found response has a 4xx status code
func (o *RevokeFDXConsentByIDNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke f d x consent by Id not found response has a 5xx status code
func (o *RevokeFDXConsentByIDNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke f d x consent by Id not found response a status code equal to that given
func (o *RevokeFDXConsentByIDNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *RevokeFDXConsentByIDNotFound) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/fdx/consents/{consentID}][%d] revokeFDXConsentByIdNotFound  %+v", 404, o.Payload)
}

func (o *RevokeFDXConsentByIDNotFound) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/fdx/consents/{consentID}][%d] revokeFDXConsentByIdNotFound  %+v", 404, o.Payload)
}

func (o *RevokeFDXConsentByIDNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeFDXConsentByIDNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeFDXConsentByIDUnprocessableEntity creates a RevokeFDXConsentByIDUnprocessableEntity with default headers values
func NewRevokeFDXConsentByIDUnprocessableEntity() *RevokeFDXConsentByIDUnprocessableEntity {
	return &RevokeFDXConsentByIDUnprocessableEntity{}
}

/*
RevokeFDXConsentByIDUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type RevokeFDXConsentByIDUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke f d x consent by Id unprocessable entity response has a 2xx status code
func (o *RevokeFDXConsentByIDUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke f d x consent by Id unprocessable entity response has a 3xx status code
func (o *RevokeFDXConsentByIDUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke f d x consent by Id unprocessable entity response has a 4xx status code
func (o *RevokeFDXConsentByIDUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke f d x consent by Id unprocessable entity response has a 5xx status code
func (o *RevokeFDXConsentByIDUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke f d x consent by Id unprocessable entity response a status code equal to that given
func (o *RevokeFDXConsentByIDUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

func (o *RevokeFDXConsentByIDUnprocessableEntity) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/fdx/consents/{consentID}][%d] revokeFDXConsentByIdUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *RevokeFDXConsentByIDUnprocessableEntity) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/fdx/consents/{consentID}][%d] revokeFDXConsentByIdUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *RevokeFDXConsentByIDUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeFDXConsentByIDUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeFDXConsentByIDTooManyRequests creates a RevokeFDXConsentByIDTooManyRequests with default headers values
func NewRevokeFDXConsentByIDTooManyRequests() *RevokeFDXConsentByIDTooManyRequests {
	return &RevokeFDXConsentByIDTooManyRequests{}
}

/*
RevokeFDXConsentByIDTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type RevokeFDXConsentByIDTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke f d x consent by Id too many requests response has a 2xx status code
func (o *RevokeFDXConsentByIDTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke f d x consent by Id too many requests response has a 3xx status code
func (o *RevokeFDXConsentByIDTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke f d x consent by Id too many requests response has a 4xx status code
func (o *RevokeFDXConsentByIDTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke f d x consent by Id too many requests response has a 5xx status code
func (o *RevokeFDXConsentByIDTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke f d x consent by Id too many requests response a status code equal to that given
func (o *RevokeFDXConsentByIDTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *RevokeFDXConsentByIDTooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/fdx/consents/{consentID}][%d] revokeFDXConsentByIdTooManyRequests  %+v", 429, o.Payload)
}

func (o *RevokeFDXConsentByIDTooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/fdx/consents/{consentID}][%d] revokeFDXConsentByIdTooManyRequests  %+v", 429, o.Payload)
}

func (o *RevokeFDXConsentByIDTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeFDXConsentByIDTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
