// Code generated by go-swagger; DO NOT EDIT.

package configuration

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identityroot/models"
)

// ImportConfigurationReader is a Reader for the ImportConfiguration structure.
type ImportConfigurationReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ImportConfigurationReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewImportConfigurationNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewImportConfigurationBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewImportConfigurationUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewImportConfigurationForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewImportConfigurationNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewImportConfigurationConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewImportConfigurationUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewImportConfigurationTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewImportConfigurationNoContent creates a ImportConfigurationNoContent with default headers values
func NewImportConfigurationNoContent() *ImportConfigurationNoContent {
	return &ImportConfigurationNoContent{}
}

/*
ImportConfigurationNoContent describes a response with status code 204, with default header values.

	configuration has been imported
*/
type ImportConfigurationNoContent struct {
}

// IsSuccess returns true when this import configuration no content response has a 2xx status code
func (o *ImportConfigurationNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this import configuration no content response has a 3xx status code
func (o *ImportConfigurationNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this import configuration no content response has a 4xx status code
func (o *ImportConfigurationNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this import configuration no content response has a 5xx status code
func (o *ImportConfigurationNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this import configuration no content response a status code equal to that given
func (o *ImportConfigurationNoContent) IsCode(code int) bool {
	return code == 204
}

func (o *ImportConfigurationNoContent) Error() string {
	return fmt.Sprintf("[PUT /configuration][%d] importConfigurationNoContent ", 204)
}

func (o *ImportConfigurationNoContent) String() string {
	return fmt.Sprintf("[PUT /configuration][%d] importConfigurationNoContent ", 204)
}

func (o *ImportConfigurationNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewImportConfigurationBadRequest creates a ImportConfigurationBadRequest with default headers values
func NewImportConfigurationBadRequest() *ImportConfigurationBadRequest {
	return &ImportConfigurationBadRequest{}
}

/*
ImportConfigurationBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type ImportConfigurationBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this import configuration bad request response has a 2xx status code
func (o *ImportConfigurationBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this import configuration bad request response has a 3xx status code
func (o *ImportConfigurationBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this import configuration bad request response has a 4xx status code
func (o *ImportConfigurationBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this import configuration bad request response has a 5xx status code
func (o *ImportConfigurationBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this import configuration bad request response a status code equal to that given
func (o *ImportConfigurationBadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *ImportConfigurationBadRequest) Error() string {
	return fmt.Sprintf("[PUT /configuration][%d] importConfigurationBadRequest  %+v", 400, o.Payload)
}

func (o *ImportConfigurationBadRequest) String() string {
	return fmt.Sprintf("[PUT /configuration][%d] importConfigurationBadRequest  %+v", 400, o.Payload)
}

func (o *ImportConfigurationBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *ImportConfigurationBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewImportConfigurationUnauthorized creates a ImportConfigurationUnauthorized with default headers values
func NewImportConfigurationUnauthorized() *ImportConfigurationUnauthorized {
	return &ImportConfigurationUnauthorized{}
}

/*
ImportConfigurationUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type ImportConfigurationUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this import configuration unauthorized response has a 2xx status code
func (o *ImportConfigurationUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this import configuration unauthorized response has a 3xx status code
func (o *ImportConfigurationUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this import configuration unauthorized response has a 4xx status code
func (o *ImportConfigurationUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this import configuration unauthorized response has a 5xx status code
func (o *ImportConfigurationUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this import configuration unauthorized response a status code equal to that given
func (o *ImportConfigurationUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *ImportConfigurationUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /configuration][%d] importConfigurationUnauthorized  %+v", 401, o.Payload)
}

func (o *ImportConfigurationUnauthorized) String() string {
	return fmt.Sprintf("[PUT /configuration][%d] importConfigurationUnauthorized  %+v", 401, o.Payload)
}

func (o *ImportConfigurationUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ImportConfigurationUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewImportConfigurationForbidden creates a ImportConfigurationForbidden with default headers values
func NewImportConfigurationForbidden() *ImportConfigurationForbidden {
	return &ImportConfigurationForbidden{}
}

/*
ImportConfigurationForbidden describes a response with status code 403, with default header values.

HttpError
*/
type ImportConfigurationForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this import configuration forbidden response has a 2xx status code
func (o *ImportConfigurationForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this import configuration forbidden response has a 3xx status code
func (o *ImportConfigurationForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this import configuration forbidden response has a 4xx status code
func (o *ImportConfigurationForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this import configuration forbidden response has a 5xx status code
func (o *ImportConfigurationForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this import configuration forbidden response a status code equal to that given
func (o *ImportConfigurationForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *ImportConfigurationForbidden) Error() string {
	return fmt.Sprintf("[PUT /configuration][%d] importConfigurationForbidden  %+v", 403, o.Payload)
}

func (o *ImportConfigurationForbidden) String() string {
	return fmt.Sprintf("[PUT /configuration][%d] importConfigurationForbidden  %+v", 403, o.Payload)
}

func (o *ImportConfigurationForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ImportConfigurationForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewImportConfigurationNotFound creates a ImportConfigurationNotFound with default headers values
func NewImportConfigurationNotFound() *ImportConfigurationNotFound {
	return &ImportConfigurationNotFound{}
}

/*
ImportConfigurationNotFound describes a response with status code 404, with default header values.

HttpError
*/
type ImportConfigurationNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this import configuration not found response has a 2xx status code
func (o *ImportConfigurationNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this import configuration not found response has a 3xx status code
func (o *ImportConfigurationNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this import configuration not found response has a 4xx status code
func (o *ImportConfigurationNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this import configuration not found response has a 5xx status code
func (o *ImportConfigurationNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this import configuration not found response a status code equal to that given
func (o *ImportConfigurationNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *ImportConfigurationNotFound) Error() string {
	return fmt.Sprintf("[PUT /configuration][%d] importConfigurationNotFound  %+v", 404, o.Payload)
}

func (o *ImportConfigurationNotFound) String() string {
	return fmt.Sprintf("[PUT /configuration][%d] importConfigurationNotFound  %+v", 404, o.Payload)
}

func (o *ImportConfigurationNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ImportConfigurationNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewImportConfigurationConflict creates a ImportConfigurationConflict with default headers values
func NewImportConfigurationConflict() *ImportConfigurationConflict {
	return &ImportConfigurationConflict{}
}

/*
ImportConfigurationConflict describes a response with status code 409, with default header values.

HttpError
*/
type ImportConfigurationConflict struct {
	Payload *models.Error
}

// IsSuccess returns true when this import configuration conflict response has a 2xx status code
func (o *ImportConfigurationConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this import configuration conflict response has a 3xx status code
func (o *ImportConfigurationConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this import configuration conflict response has a 4xx status code
func (o *ImportConfigurationConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this import configuration conflict response has a 5xx status code
func (o *ImportConfigurationConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this import configuration conflict response a status code equal to that given
func (o *ImportConfigurationConflict) IsCode(code int) bool {
	return code == 409
}

func (o *ImportConfigurationConflict) Error() string {
	return fmt.Sprintf("[PUT /configuration][%d] importConfigurationConflict  %+v", 409, o.Payload)
}

func (o *ImportConfigurationConflict) String() string {
	return fmt.Sprintf("[PUT /configuration][%d] importConfigurationConflict  %+v", 409, o.Payload)
}

func (o *ImportConfigurationConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *ImportConfigurationConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewImportConfigurationUnprocessableEntity creates a ImportConfigurationUnprocessableEntity with default headers values
func NewImportConfigurationUnprocessableEntity() *ImportConfigurationUnprocessableEntity {
	return &ImportConfigurationUnprocessableEntity{}
}

/*
ImportConfigurationUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type ImportConfigurationUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this import configuration unprocessable entity response has a 2xx status code
func (o *ImportConfigurationUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this import configuration unprocessable entity response has a 3xx status code
func (o *ImportConfigurationUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this import configuration unprocessable entity response has a 4xx status code
func (o *ImportConfigurationUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this import configuration unprocessable entity response has a 5xx status code
func (o *ImportConfigurationUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this import configuration unprocessable entity response a status code equal to that given
func (o *ImportConfigurationUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

func (o *ImportConfigurationUnprocessableEntity) Error() string {
	return fmt.Sprintf("[PUT /configuration][%d] importConfigurationUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *ImportConfigurationUnprocessableEntity) String() string {
	return fmt.Sprintf("[PUT /configuration][%d] importConfigurationUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *ImportConfigurationUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *ImportConfigurationUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewImportConfigurationTooManyRequests creates a ImportConfigurationTooManyRequests with default headers values
func NewImportConfigurationTooManyRequests() *ImportConfigurationTooManyRequests {
	return &ImportConfigurationTooManyRequests{}
}

/*
ImportConfigurationTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type ImportConfigurationTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this import configuration too many requests response has a 2xx status code
func (o *ImportConfigurationTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this import configuration too many requests response has a 3xx status code
func (o *ImportConfigurationTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this import configuration too many requests response has a 4xx status code
func (o *ImportConfigurationTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this import configuration too many requests response has a 5xx status code
func (o *ImportConfigurationTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this import configuration too many requests response a status code equal to that given
func (o *ImportConfigurationTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *ImportConfigurationTooManyRequests) Error() string {
	return fmt.Sprintf("[PUT /configuration][%d] importConfigurationTooManyRequests  %+v", 429, o.Payload)
}

func (o *ImportConfigurationTooManyRequests) String() string {
	return fmt.Sprintf("[PUT /configuration][%d] importConfigurationTooManyRequests  %+v", 429, o.Payload)
}

func (o *ImportConfigurationTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ImportConfigurationTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
