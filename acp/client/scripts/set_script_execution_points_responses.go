// Code generated by go-swagger; DO NOT EDIT.

package scripts

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/acp/models"
)

// SetScriptExecutionPointsReader is a Reader for the SetScriptExecutionPoints structure.
type SetScriptExecutionPointsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SetScriptExecutionPointsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSetScriptExecutionPointsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewSetScriptExecutionPointsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewSetScriptExecutionPointsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSetScriptExecutionPointsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSetScriptExecutionPointsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewSetScriptExecutionPointsConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewSetScriptExecutionPointsUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSetScriptExecutionPointsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewSetScriptExecutionPointsOK creates a SetScriptExecutionPointsOK with default headers values
func NewSetScriptExecutionPointsOK() *SetScriptExecutionPointsOK {
	return &SetScriptExecutionPointsOK{}
}

/* SetScriptExecutionPointsOK describes a response with status code 200, with default header values.

ScriptExecutionPoints
*/
type SetScriptExecutionPointsOK struct {
	Payload *models.ScriptExecutionPoints
}

func (o *SetScriptExecutionPointsOK) Error() string {
	return fmt.Sprintf("[PUT /api/admin/{tid}/servers/{aid}/script-execution-points][%d] setScriptExecutionPointsOK  %+v", 200, o.Payload)
}
func (o *SetScriptExecutionPointsOK) GetPayload() *models.ScriptExecutionPoints {
	return o.Payload
}

func (o *SetScriptExecutionPointsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ScriptExecutionPoints)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetScriptExecutionPointsBadRequest creates a SetScriptExecutionPointsBadRequest with default headers values
func NewSetScriptExecutionPointsBadRequest() *SetScriptExecutionPointsBadRequest {
	return &SetScriptExecutionPointsBadRequest{}
}

/* SetScriptExecutionPointsBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type SetScriptExecutionPointsBadRequest struct {
	Payload *models.Error
}

func (o *SetScriptExecutionPointsBadRequest) Error() string {
	return fmt.Sprintf("[PUT /api/admin/{tid}/servers/{aid}/script-execution-points][%d] setScriptExecutionPointsBadRequest  %+v", 400, o.Payload)
}
func (o *SetScriptExecutionPointsBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetScriptExecutionPointsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetScriptExecutionPointsUnauthorized creates a SetScriptExecutionPointsUnauthorized with default headers values
func NewSetScriptExecutionPointsUnauthorized() *SetScriptExecutionPointsUnauthorized {
	return &SetScriptExecutionPointsUnauthorized{}
}

/* SetScriptExecutionPointsUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type SetScriptExecutionPointsUnauthorized struct {
	Payload *models.Error
}

func (o *SetScriptExecutionPointsUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /api/admin/{tid}/servers/{aid}/script-execution-points][%d] setScriptExecutionPointsUnauthorized  %+v", 401, o.Payload)
}
func (o *SetScriptExecutionPointsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetScriptExecutionPointsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetScriptExecutionPointsForbidden creates a SetScriptExecutionPointsForbidden with default headers values
func NewSetScriptExecutionPointsForbidden() *SetScriptExecutionPointsForbidden {
	return &SetScriptExecutionPointsForbidden{}
}

/* SetScriptExecutionPointsForbidden describes a response with status code 403, with default header values.

HttpError
*/
type SetScriptExecutionPointsForbidden struct {
	Payload *models.Error
}

func (o *SetScriptExecutionPointsForbidden) Error() string {
	return fmt.Sprintf("[PUT /api/admin/{tid}/servers/{aid}/script-execution-points][%d] setScriptExecutionPointsForbidden  %+v", 403, o.Payload)
}
func (o *SetScriptExecutionPointsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetScriptExecutionPointsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetScriptExecutionPointsNotFound creates a SetScriptExecutionPointsNotFound with default headers values
func NewSetScriptExecutionPointsNotFound() *SetScriptExecutionPointsNotFound {
	return &SetScriptExecutionPointsNotFound{}
}

/* SetScriptExecutionPointsNotFound describes a response with status code 404, with default header values.

HttpError
*/
type SetScriptExecutionPointsNotFound struct {
	Payload *models.Error
}

func (o *SetScriptExecutionPointsNotFound) Error() string {
	return fmt.Sprintf("[PUT /api/admin/{tid}/servers/{aid}/script-execution-points][%d] setScriptExecutionPointsNotFound  %+v", 404, o.Payload)
}
func (o *SetScriptExecutionPointsNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetScriptExecutionPointsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetScriptExecutionPointsConflict creates a SetScriptExecutionPointsConflict with default headers values
func NewSetScriptExecutionPointsConflict() *SetScriptExecutionPointsConflict {
	return &SetScriptExecutionPointsConflict{}
}

/* SetScriptExecutionPointsConflict describes a response with status code 409, with default header values.

HttpError
*/
type SetScriptExecutionPointsConflict struct {
	Payload *models.Error
}

func (o *SetScriptExecutionPointsConflict) Error() string {
	return fmt.Sprintf("[PUT /api/admin/{tid}/servers/{aid}/script-execution-points][%d] setScriptExecutionPointsConflict  %+v", 409, o.Payload)
}
func (o *SetScriptExecutionPointsConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetScriptExecutionPointsConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetScriptExecutionPointsUnprocessableEntity creates a SetScriptExecutionPointsUnprocessableEntity with default headers values
func NewSetScriptExecutionPointsUnprocessableEntity() *SetScriptExecutionPointsUnprocessableEntity {
	return &SetScriptExecutionPointsUnprocessableEntity{}
}

/* SetScriptExecutionPointsUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type SetScriptExecutionPointsUnprocessableEntity struct {
	Payload *models.Error
}

func (o *SetScriptExecutionPointsUnprocessableEntity) Error() string {
	return fmt.Sprintf("[PUT /api/admin/{tid}/servers/{aid}/script-execution-points][%d] setScriptExecutionPointsUnprocessableEntity  %+v", 422, o.Payload)
}
func (o *SetScriptExecutionPointsUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetScriptExecutionPointsUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetScriptExecutionPointsTooManyRequests creates a SetScriptExecutionPointsTooManyRequests with default headers values
func NewSetScriptExecutionPointsTooManyRequests() *SetScriptExecutionPointsTooManyRequests {
	return &SetScriptExecutionPointsTooManyRequests{}
}

/* SetScriptExecutionPointsTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type SetScriptExecutionPointsTooManyRequests struct {
	Payload *models.Error
}

func (o *SetScriptExecutionPointsTooManyRequests) Error() string {
	return fmt.Sprintf("[PUT /api/admin/{tid}/servers/{aid}/script-execution-points][%d] setScriptExecutionPointsTooManyRequests  %+v", 429, o.Payload)
}
func (o *SetScriptExecutionPointsTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetScriptExecutionPointsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}