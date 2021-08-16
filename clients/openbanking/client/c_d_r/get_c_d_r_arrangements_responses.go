// Code generated by go-swagger; DO NOT EDIT.

package c_d_r

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/openbanking/models"
)

// GetCDRArrangementsReader is a Reader for the GetCDRArrangements structure.
type GetCDRArrangementsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetCDRArrangementsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetCDRArrangementsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetCDRArrangementsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetCDRArrangementsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetCDRArrangementsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetCDRArrangementsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewGetCDRArrangementsUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetCDRArrangementsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetCDRArrangementsOK creates a GetCDRArrangementsOK with default headers values
func NewGetCDRArrangementsOK() *GetCDRArrangementsOK {
	return &GetCDRArrangementsOK{}
}

/* GetCDRArrangementsOK describes a response with status code 200, with default header values.

CDRArrangements
*/
type GetCDRArrangementsOK struct {
	Payload *models.CDRArrangements
}

func (o *GetCDRArrangementsOK) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/cdr/arrangements][%d] getCDRArrangementsOK  %+v", 200, o.Payload)
}
func (o *GetCDRArrangementsOK) GetPayload() *models.CDRArrangements {
	return o.Payload
}

func (o *GetCDRArrangementsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.CDRArrangements)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetCDRArrangementsBadRequest creates a GetCDRArrangementsBadRequest with default headers values
func NewGetCDRArrangementsBadRequest() *GetCDRArrangementsBadRequest {
	return &GetCDRArrangementsBadRequest{}
}

/* GetCDRArrangementsBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type GetCDRArrangementsBadRequest struct {
	Payload *models.Error
}

func (o *GetCDRArrangementsBadRequest) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/cdr/arrangements][%d] getCDRArrangementsBadRequest  %+v", 400, o.Payload)
}
func (o *GetCDRArrangementsBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetCDRArrangementsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetCDRArrangementsUnauthorized creates a GetCDRArrangementsUnauthorized with default headers values
func NewGetCDRArrangementsUnauthorized() *GetCDRArrangementsUnauthorized {
	return &GetCDRArrangementsUnauthorized{}
}

/* GetCDRArrangementsUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type GetCDRArrangementsUnauthorized struct {
	Payload *models.Error
}

func (o *GetCDRArrangementsUnauthorized) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/cdr/arrangements][%d] getCDRArrangementsUnauthorized  %+v", 401, o.Payload)
}
func (o *GetCDRArrangementsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetCDRArrangementsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetCDRArrangementsForbidden creates a GetCDRArrangementsForbidden with default headers values
func NewGetCDRArrangementsForbidden() *GetCDRArrangementsForbidden {
	return &GetCDRArrangementsForbidden{}
}

/* GetCDRArrangementsForbidden describes a response with status code 403, with default header values.

HttpError
*/
type GetCDRArrangementsForbidden struct {
	Payload *models.Error
}

func (o *GetCDRArrangementsForbidden) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/cdr/arrangements][%d] getCDRArrangementsForbidden  %+v", 403, o.Payload)
}
func (o *GetCDRArrangementsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetCDRArrangementsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetCDRArrangementsNotFound creates a GetCDRArrangementsNotFound with default headers values
func NewGetCDRArrangementsNotFound() *GetCDRArrangementsNotFound {
	return &GetCDRArrangementsNotFound{}
}

/* GetCDRArrangementsNotFound describes a response with status code 404, with default header values.

HttpError
*/
type GetCDRArrangementsNotFound struct {
	Payload *models.Error
}

func (o *GetCDRArrangementsNotFound) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/cdr/arrangements][%d] getCDRArrangementsNotFound  %+v", 404, o.Payload)
}
func (o *GetCDRArrangementsNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetCDRArrangementsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetCDRArrangementsUnprocessableEntity creates a GetCDRArrangementsUnprocessableEntity with default headers values
func NewGetCDRArrangementsUnprocessableEntity() *GetCDRArrangementsUnprocessableEntity {
	return &GetCDRArrangementsUnprocessableEntity{}
}

/* GetCDRArrangementsUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type GetCDRArrangementsUnprocessableEntity struct {
	Payload *models.Error
}

func (o *GetCDRArrangementsUnprocessableEntity) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/cdr/arrangements][%d] getCDRArrangementsUnprocessableEntity  %+v", 422, o.Payload)
}
func (o *GetCDRArrangementsUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetCDRArrangementsUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetCDRArrangementsTooManyRequests creates a GetCDRArrangementsTooManyRequests with default headers values
func NewGetCDRArrangementsTooManyRequests() *GetCDRArrangementsTooManyRequests {
	return &GetCDRArrangementsTooManyRequests{}
}

/* GetCDRArrangementsTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type GetCDRArrangementsTooManyRequests struct {
	Payload *models.Error
}

func (o *GetCDRArrangementsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/cdr/arrangements][%d] getCDRArrangementsTooManyRequests  %+v", 429, o.Payload)
}
func (o *GetCDRArrangementsTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetCDRArrangementsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}