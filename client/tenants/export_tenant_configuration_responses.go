// Code generated by go-swagger; DO NOT EDIT.

package tenants

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/models"
)

// ExportTenantConfigurationReader is a Reader for the ExportTenantConfiguration structure.
type ExportTenantConfigurationReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ExportTenantConfigurationReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewExportTenantConfigurationOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewExportTenantConfigurationBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewExportTenantConfigurationUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewExportTenantConfigurationForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewExportTenantConfigurationNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewExportTenantConfigurationUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewExportTenantConfigurationOK creates a ExportTenantConfigurationOK with default headers values
func NewExportTenantConfigurationOK() *ExportTenantConfigurationOK {
	return &ExportTenantConfigurationOK{}
}

/* ExportTenantConfigurationOK describes a response with status code 200, with default header values.

TenantDump
*/
type ExportTenantConfigurationOK struct {
	Payload *models.TenantDump
}

func (o *ExportTenantConfigurationOK) Error() string {
	return fmt.Sprintf("[GET /api/system/{tid}/configuration][%d] exportTenantConfigurationOK  %+v", 200, o.Payload)
}
func (o *ExportTenantConfigurationOK) GetPayload() *models.TenantDump {
	return o.Payload
}

func (o *ExportTenantConfigurationOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.TenantDump)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewExportTenantConfigurationBadRequest creates a ExportTenantConfigurationBadRequest with default headers values
func NewExportTenantConfigurationBadRequest() *ExportTenantConfigurationBadRequest {
	return &ExportTenantConfigurationBadRequest{}
}

/* ExportTenantConfigurationBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type ExportTenantConfigurationBadRequest struct {
	Payload *models.Error
}

func (o *ExportTenantConfigurationBadRequest) Error() string {
	return fmt.Sprintf("[GET /api/system/{tid}/configuration][%d] exportTenantConfigurationBadRequest  %+v", 400, o.Payload)
}
func (o *ExportTenantConfigurationBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *ExportTenantConfigurationBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewExportTenantConfigurationUnauthorized creates a ExportTenantConfigurationUnauthorized with default headers values
func NewExportTenantConfigurationUnauthorized() *ExportTenantConfigurationUnauthorized {
	return &ExportTenantConfigurationUnauthorized{}
}

/* ExportTenantConfigurationUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type ExportTenantConfigurationUnauthorized struct {
	Payload *models.Error
}

func (o *ExportTenantConfigurationUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/system/{tid}/configuration][%d] exportTenantConfigurationUnauthorized  %+v", 401, o.Payload)
}
func (o *ExportTenantConfigurationUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ExportTenantConfigurationUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewExportTenantConfigurationForbidden creates a ExportTenantConfigurationForbidden with default headers values
func NewExportTenantConfigurationForbidden() *ExportTenantConfigurationForbidden {
	return &ExportTenantConfigurationForbidden{}
}

/* ExportTenantConfigurationForbidden describes a response with status code 403, with default header values.

HttpError
*/
type ExportTenantConfigurationForbidden struct {
	Payload *models.Error
}

func (o *ExportTenantConfigurationForbidden) Error() string {
	return fmt.Sprintf("[GET /api/system/{tid}/configuration][%d] exportTenantConfigurationForbidden  %+v", 403, o.Payload)
}
func (o *ExportTenantConfigurationForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ExportTenantConfigurationForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewExportTenantConfigurationNotFound creates a ExportTenantConfigurationNotFound with default headers values
func NewExportTenantConfigurationNotFound() *ExportTenantConfigurationNotFound {
	return &ExportTenantConfigurationNotFound{}
}

/* ExportTenantConfigurationNotFound describes a response with status code 404, with default header values.

HttpError
*/
type ExportTenantConfigurationNotFound struct {
	Payload *models.Error
}

func (o *ExportTenantConfigurationNotFound) Error() string {
	return fmt.Sprintf("[GET /api/system/{tid}/configuration][%d] exportTenantConfigurationNotFound  %+v", 404, o.Payload)
}
func (o *ExportTenantConfigurationNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ExportTenantConfigurationNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewExportTenantConfigurationUnprocessableEntity creates a ExportTenantConfigurationUnprocessableEntity with default headers values
func NewExportTenantConfigurationUnprocessableEntity() *ExportTenantConfigurationUnprocessableEntity {
	return &ExportTenantConfigurationUnprocessableEntity{}
}

/* ExportTenantConfigurationUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type ExportTenantConfigurationUnprocessableEntity struct {
	Payload *models.Error
}

func (o *ExportTenantConfigurationUnprocessableEntity) Error() string {
	return fmt.Sprintf("[GET /api/system/{tid}/configuration][%d] exportTenantConfigurationUnprocessableEntity  %+v", 422, o.Payload)
}
func (o *ExportTenantConfigurationUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *ExportTenantConfigurationUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
