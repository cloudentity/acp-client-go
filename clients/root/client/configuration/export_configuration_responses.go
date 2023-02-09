// Code generated by go-swagger; DO NOT EDIT.

package configuration

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/root/models"
)

// ExportConfigurationReader is a Reader for the ExportConfiguration structure.
type ExportConfigurationReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ExportConfigurationReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewExportConfigurationOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewExportConfigurationBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewExportConfigurationUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewExportConfigurationForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewExportConfigurationNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewExportConfigurationUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewExportConfigurationTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewExportConfigurationOK creates a ExportConfigurationOK with default headers values
func NewExportConfigurationOK() *ExportConfigurationOK {
	return &ExportConfigurationOK{}
}

/*
ExportConfigurationOK describes a response with status code 200, with default header values.

Dump
*/
type ExportConfigurationOK struct {
	Payload *models.Dump
}

// IsSuccess returns true when this export configuration o k response has a 2xx status code
func (o *ExportConfigurationOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this export configuration o k response has a 3xx status code
func (o *ExportConfigurationOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this export configuration o k response has a 4xx status code
func (o *ExportConfigurationOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this export configuration o k response has a 5xx status code
func (o *ExportConfigurationOK) IsServerError() bool {
	return false
}

// IsCode returns true when this export configuration o k response a status code equal to that given
func (o *ExportConfigurationOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the export configuration o k response
func (o *ExportConfigurationOK) Code() int {
	return 200
}

func (o *ExportConfigurationOK) Error() string {
	return fmt.Sprintf("[GET /api/system/configuration][%d] exportConfigurationOK  %+v", 200, o.Payload)
}

func (o *ExportConfigurationOK) String() string {
	return fmt.Sprintf("[GET /api/system/configuration][%d] exportConfigurationOK  %+v", 200, o.Payload)
}

func (o *ExportConfigurationOK) GetPayload() *models.Dump {
	return o.Payload
}

func (o *ExportConfigurationOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Dump)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewExportConfigurationBadRequest creates a ExportConfigurationBadRequest with default headers values
func NewExportConfigurationBadRequest() *ExportConfigurationBadRequest {
	return &ExportConfigurationBadRequest{}
}

/*
ExportConfigurationBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type ExportConfigurationBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this export configuration bad request response has a 2xx status code
func (o *ExportConfigurationBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this export configuration bad request response has a 3xx status code
func (o *ExportConfigurationBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this export configuration bad request response has a 4xx status code
func (o *ExportConfigurationBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this export configuration bad request response has a 5xx status code
func (o *ExportConfigurationBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this export configuration bad request response a status code equal to that given
func (o *ExportConfigurationBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the export configuration bad request response
func (o *ExportConfigurationBadRequest) Code() int {
	return 400
}

func (o *ExportConfigurationBadRequest) Error() string {
	return fmt.Sprintf("[GET /api/system/configuration][%d] exportConfigurationBadRequest  %+v", 400, o.Payload)
}

func (o *ExportConfigurationBadRequest) String() string {
	return fmt.Sprintf("[GET /api/system/configuration][%d] exportConfigurationBadRequest  %+v", 400, o.Payload)
}

func (o *ExportConfigurationBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *ExportConfigurationBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewExportConfigurationUnauthorized creates a ExportConfigurationUnauthorized with default headers values
func NewExportConfigurationUnauthorized() *ExportConfigurationUnauthorized {
	return &ExportConfigurationUnauthorized{}
}

/*
ExportConfigurationUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type ExportConfigurationUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this export configuration unauthorized response has a 2xx status code
func (o *ExportConfigurationUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this export configuration unauthorized response has a 3xx status code
func (o *ExportConfigurationUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this export configuration unauthorized response has a 4xx status code
func (o *ExportConfigurationUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this export configuration unauthorized response has a 5xx status code
func (o *ExportConfigurationUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this export configuration unauthorized response a status code equal to that given
func (o *ExportConfigurationUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the export configuration unauthorized response
func (o *ExportConfigurationUnauthorized) Code() int {
	return 401
}

func (o *ExportConfigurationUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/system/configuration][%d] exportConfigurationUnauthorized  %+v", 401, o.Payload)
}

func (o *ExportConfigurationUnauthorized) String() string {
	return fmt.Sprintf("[GET /api/system/configuration][%d] exportConfigurationUnauthorized  %+v", 401, o.Payload)
}

func (o *ExportConfigurationUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ExportConfigurationUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewExportConfigurationForbidden creates a ExportConfigurationForbidden with default headers values
func NewExportConfigurationForbidden() *ExportConfigurationForbidden {
	return &ExportConfigurationForbidden{}
}

/*
ExportConfigurationForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ExportConfigurationForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this export configuration forbidden response has a 2xx status code
func (o *ExportConfigurationForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this export configuration forbidden response has a 3xx status code
func (o *ExportConfigurationForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this export configuration forbidden response has a 4xx status code
func (o *ExportConfigurationForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this export configuration forbidden response has a 5xx status code
func (o *ExportConfigurationForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this export configuration forbidden response a status code equal to that given
func (o *ExportConfigurationForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the export configuration forbidden response
func (o *ExportConfigurationForbidden) Code() int {
	return 403
}

func (o *ExportConfigurationForbidden) Error() string {
	return fmt.Sprintf("[GET /api/system/configuration][%d] exportConfigurationForbidden  %+v", 403, o.Payload)
}

func (o *ExportConfigurationForbidden) String() string {
	return fmt.Sprintf("[GET /api/system/configuration][%d] exportConfigurationForbidden  %+v", 403, o.Payload)
}

func (o *ExportConfigurationForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ExportConfigurationForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewExportConfigurationNotFound creates a ExportConfigurationNotFound with default headers values
func NewExportConfigurationNotFound() *ExportConfigurationNotFound {
	return &ExportConfigurationNotFound{}
}

/*
ExportConfigurationNotFound describes a response with status code 404, with default header values.

Not found
*/
type ExportConfigurationNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this export configuration not found response has a 2xx status code
func (o *ExportConfigurationNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this export configuration not found response has a 3xx status code
func (o *ExportConfigurationNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this export configuration not found response has a 4xx status code
func (o *ExportConfigurationNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this export configuration not found response has a 5xx status code
func (o *ExportConfigurationNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this export configuration not found response a status code equal to that given
func (o *ExportConfigurationNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the export configuration not found response
func (o *ExportConfigurationNotFound) Code() int {
	return 404
}

func (o *ExportConfigurationNotFound) Error() string {
	return fmt.Sprintf("[GET /api/system/configuration][%d] exportConfigurationNotFound  %+v", 404, o.Payload)
}

func (o *ExportConfigurationNotFound) String() string {
	return fmt.Sprintf("[GET /api/system/configuration][%d] exportConfigurationNotFound  %+v", 404, o.Payload)
}

func (o *ExportConfigurationNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ExportConfigurationNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewExportConfigurationUnprocessableEntity creates a ExportConfigurationUnprocessableEntity with default headers values
func NewExportConfigurationUnprocessableEntity() *ExportConfigurationUnprocessableEntity {
	return &ExportConfigurationUnprocessableEntity{}
}

/*
ExportConfigurationUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type ExportConfigurationUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this export configuration unprocessable entity response has a 2xx status code
func (o *ExportConfigurationUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this export configuration unprocessable entity response has a 3xx status code
func (o *ExportConfigurationUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this export configuration unprocessable entity response has a 4xx status code
func (o *ExportConfigurationUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this export configuration unprocessable entity response has a 5xx status code
func (o *ExportConfigurationUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this export configuration unprocessable entity response a status code equal to that given
func (o *ExportConfigurationUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the export configuration unprocessable entity response
func (o *ExportConfigurationUnprocessableEntity) Code() int {
	return 422
}

func (o *ExportConfigurationUnprocessableEntity) Error() string {
	return fmt.Sprintf("[GET /api/system/configuration][%d] exportConfigurationUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *ExportConfigurationUnprocessableEntity) String() string {
	return fmt.Sprintf("[GET /api/system/configuration][%d] exportConfigurationUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *ExportConfigurationUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *ExportConfigurationUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewExportConfigurationTooManyRequests creates a ExportConfigurationTooManyRequests with default headers values
func NewExportConfigurationTooManyRequests() *ExportConfigurationTooManyRequests {
	return &ExportConfigurationTooManyRequests{}
}

/*
ExportConfigurationTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type ExportConfigurationTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this export configuration too many requests response has a 2xx status code
func (o *ExportConfigurationTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this export configuration too many requests response has a 3xx status code
func (o *ExportConfigurationTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this export configuration too many requests response has a 4xx status code
func (o *ExportConfigurationTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this export configuration too many requests response has a 5xx status code
func (o *ExportConfigurationTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this export configuration too many requests response a status code equal to that given
func (o *ExportConfigurationTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the export configuration too many requests response
func (o *ExportConfigurationTooManyRequests) Code() int {
	return 429
}

func (o *ExportConfigurationTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /api/system/configuration][%d] exportConfigurationTooManyRequests  %+v", 429, o.Payload)
}

func (o *ExportConfigurationTooManyRequests) String() string {
	return fmt.Sprintf("[GET /api/system/configuration][%d] exportConfigurationTooManyRequests  %+v", 429, o.Payload)
}

func (o *ExportConfigurationTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ExportConfigurationTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
