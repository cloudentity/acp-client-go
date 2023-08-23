// Code generated by go-swagger; DO NOT EDIT.

package templates

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// ImportThemeTemplatesReader is a Reader for the ImportThemeTemplates structure.
type ImportThemeTemplatesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ImportThemeTemplatesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewImportThemeTemplatesNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewImportThemeTemplatesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewImportThemeTemplatesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewImportThemeTemplatesNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewImportThemeTemplatesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewImportThemeTemplatesNoContent creates a ImportThemeTemplatesNoContent with default headers values
func NewImportThemeTemplatesNoContent() *ImportThemeTemplatesNoContent {
	return &ImportThemeTemplatesNoContent{}
}

/*
ImportThemeTemplatesNoContent describes a response with status code 204, with default header values.

	Theme templates have been inserted or updated
*/
type ImportThemeTemplatesNoContent struct {
}

// IsSuccess returns true when this import theme templates no content response has a 2xx status code
func (o *ImportThemeTemplatesNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this import theme templates no content response has a 3xx status code
func (o *ImportThemeTemplatesNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this import theme templates no content response has a 4xx status code
func (o *ImportThemeTemplatesNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this import theme templates no content response has a 5xx status code
func (o *ImportThemeTemplatesNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this import theme templates no content response a status code equal to that given
func (o *ImportThemeTemplatesNoContent) IsCode(code int) bool {
	return code == 204
}

func (o *ImportThemeTemplatesNoContent) Error() string {
	return fmt.Sprintf("[POST /theme/{themeID}/templates/zip][%d] importThemeTemplatesNoContent ", 204)
}

func (o *ImportThemeTemplatesNoContent) String() string {
	return fmt.Sprintf("[POST /theme/{themeID}/templates/zip][%d] importThemeTemplatesNoContent ", 204)
}

func (o *ImportThemeTemplatesNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewImportThemeTemplatesUnauthorized creates a ImportThemeTemplatesUnauthorized with default headers values
func NewImportThemeTemplatesUnauthorized() *ImportThemeTemplatesUnauthorized {
	return &ImportThemeTemplatesUnauthorized{}
}

/*
ImportThemeTemplatesUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type ImportThemeTemplatesUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this import theme templates unauthorized response has a 2xx status code
func (o *ImportThemeTemplatesUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this import theme templates unauthorized response has a 3xx status code
func (o *ImportThemeTemplatesUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this import theme templates unauthorized response has a 4xx status code
func (o *ImportThemeTemplatesUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this import theme templates unauthorized response has a 5xx status code
func (o *ImportThemeTemplatesUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this import theme templates unauthorized response a status code equal to that given
func (o *ImportThemeTemplatesUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *ImportThemeTemplatesUnauthorized) Error() string {
	return fmt.Sprintf("[POST /theme/{themeID}/templates/zip][%d] importThemeTemplatesUnauthorized  %+v", 401, o.Payload)
}

func (o *ImportThemeTemplatesUnauthorized) String() string {
	return fmt.Sprintf("[POST /theme/{themeID}/templates/zip][%d] importThemeTemplatesUnauthorized  %+v", 401, o.Payload)
}

func (o *ImportThemeTemplatesUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ImportThemeTemplatesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewImportThemeTemplatesForbidden creates a ImportThemeTemplatesForbidden with default headers values
func NewImportThemeTemplatesForbidden() *ImportThemeTemplatesForbidden {
	return &ImportThemeTemplatesForbidden{}
}

/*
ImportThemeTemplatesForbidden describes a response with status code 403, with default header values.

HttpError
*/
type ImportThemeTemplatesForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this import theme templates forbidden response has a 2xx status code
func (o *ImportThemeTemplatesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this import theme templates forbidden response has a 3xx status code
func (o *ImportThemeTemplatesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this import theme templates forbidden response has a 4xx status code
func (o *ImportThemeTemplatesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this import theme templates forbidden response has a 5xx status code
func (o *ImportThemeTemplatesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this import theme templates forbidden response a status code equal to that given
func (o *ImportThemeTemplatesForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *ImportThemeTemplatesForbidden) Error() string {
	return fmt.Sprintf("[POST /theme/{themeID}/templates/zip][%d] importThemeTemplatesForbidden  %+v", 403, o.Payload)
}

func (o *ImportThemeTemplatesForbidden) String() string {
	return fmt.Sprintf("[POST /theme/{themeID}/templates/zip][%d] importThemeTemplatesForbidden  %+v", 403, o.Payload)
}

func (o *ImportThemeTemplatesForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ImportThemeTemplatesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewImportThemeTemplatesNotFound creates a ImportThemeTemplatesNotFound with default headers values
func NewImportThemeTemplatesNotFound() *ImportThemeTemplatesNotFound {
	return &ImportThemeTemplatesNotFound{}
}

/*
ImportThemeTemplatesNotFound describes a response with status code 404, with default header values.

HttpError
*/
type ImportThemeTemplatesNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this import theme templates not found response has a 2xx status code
func (o *ImportThemeTemplatesNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this import theme templates not found response has a 3xx status code
func (o *ImportThemeTemplatesNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this import theme templates not found response has a 4xx status code
func (o *ImportThemeTemplatesNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this import theme templates not found response has a 5xx status code
func (o *ImportThemeTemplatesNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this import theme templates not found response a status code equal to that given
func (o *ImportThemeTemplatesNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *ImportThemeTemplatesNotFound) Error() string {
	return fmt.Sprintf("[POST /theme/{themeID}/templates/zip][%d] importThemeTemplatesNotFound  %+v", 404, o.Payload)
}

func (o *ImportThemeTemplatesNotFound) String() string {
	return fmt.Sprintf("[POST /theme/{themeID}/templates/zip][%d] importThemeTemplatesNotFound  %+v", 404, o.Payload)
}

func (o *ImportThemeTemplatesNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ImportThemeTemplatesNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewImportThemeTemplatesTooManyRequests creates a ImportThemeTemplatesTooManyRequests with default headers values
func NewImportThemeTemplatesTooManyRequests() *ImportThemeTemplatesTooManyRequests {
	return &ImportThemeTemplatesTooManyRequests{}
}

/*
ImportThemeTemplatesTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type ImportThemeTemplatesTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this import theme templates too many requests response has a 2xx status code
func (o *ImportThemeTemplatesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this import theme templates too many requests response has a 3xx status code
func (o *ImportThemeTemplatesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this import theme templates too many requests response has a 4xx status code
func (o *ImportThemeTemplatesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this import theme templates too many requests response has a 5xx status code
func (o *ImportThemeTemplatesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this import theme templates too many requests response a status code equal to that given
func (o *ImportThemeTemplatesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *ImportThemeTemplatesTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /theme/{themeID}/templates/zip][%d] importThemeTemplatesTooManyRequests  %+v", 429, o.Payload)
}

func (o *ImportThemeTemplatesTooManyRequests) String() string {
	return fmt.Sprintf("[POST /theme/{themeID}/templates/zip][%d] importThemeTemplatesTooManyRequests  %+v", 429, o.Payload)
}

func (o *ImportThemeTemplatesTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ImportThemeTemplatesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}