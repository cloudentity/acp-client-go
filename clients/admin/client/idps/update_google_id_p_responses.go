// Code generated by go-swagger; DO NOT EDIT.

package idps

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// UpdateGoogleIDPReader is a Reader for the UpdateGoogleIDP structure.
type UpdateGoogleIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateGoogleIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateGoogleIDPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateGoogleIDPBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewUpdateGoogleIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdateGoogleIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateGoogleIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewUpdateGoogleIDPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdateGoogleIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewUpdateGoogleIDPOK creates a UpdateGoogleIDPOK with default headers values
func NewUpdateGoogleIDPOK() *UpdateGoogleIDPOK {
	return &UpdateGoogleIDPOK{}
}

/*
UpdateGoogleIDPOK describes a response with status code 200, with default header values.

GoogleIDP
*/
type UpdateGoogleIDPOK struct {
	Payload *models.GoogleIDP
}

// IsSuccess returns true when this update google Id p o k response has a 2xx status code
func (o *UpdateGoogleIDPOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update google Id p o k response has a 3xx status code
func (o *UpdateGoogleIDPOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update google Id p o k response has a 4xx status code
func (o *UpdateGoogleIDPOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update google Id p o k response has a 5xx status code
func (o *UpdateGoogleIDPOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update google Id p o k response a status code equal to that given
func (o *UpdateGoogleIDPOK) IsCode(code int) bool {
	return code == 200
}

func (o *UpdateGoogleIDPOK) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/google/{iid}][%d] updateGoogleIdPOK  %+v", 200, o.Payload)
}

func (o *UpdateGoogleIDPOK) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/google/{iid}][%d] updateGoogleIdPOK  %+v", 200, o.Payload)
}

func (o *UpdateGoogleIDPOK) GetPayload() *models.GoogleIDP {
	return o.Payload
}

func (o *UpdateGoogleIDPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GoogleIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateGoogleIDPBadRequest creates a UpdateGoogleIDPBadRequest with default headers values
func NewUpdateGoogleIDPBadRequest() *UpdateGoogleIDPBadRequest {
	return &UpdateGoogleIDPBadRequest{}
}

/*
UpdateGoogleIDPBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type UpdateGoogleIDPBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this update google Id p bad request response has a 2xx status code
func (o *UpdateGoogleIDPBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update google Id p bad request response has a 3xx status code
func (o *UpdateGoogleIDPBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update google Id p bad request response has a 4xx status code
func (o *UpdateGoogleIDPBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this update google Id p bad request response has a 5xx status code
func (o *UpdateGoogleIDPBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this update google Id p bad request response a status code equal to that given
func (o *UpdateGoogleIDPBadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *UpdateGoogleIDPBadRequest) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/google/{iid}][%d] updateGoogleIdPBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateGoogleIDPBadRequest) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/google/{iid}][%d] updateGoogleIdPBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateGoogleIDPBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateGoogleIDPBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateGoogleIDPUnauthorized creates a UpdateGoogleIDPUnauthorized with default headers values
func NewUpdateGoogleIDPUnauthorized() *UpdateGoogleIDPUnauthorized {
	return &UpdateGoogleIDPUnauthorized{}
}

/*
UpdateGoogleIDPUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type UpdateGoogleIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this update google Id p unauthorized response has a 2xx status code
func (o *UpdateGoogleIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update google Id p unauthorized response has a 3xx status code
func (o *UpdateGoogleIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update google Id p unauthorized response has a 4xx status code
func (o *UpdateGoogleIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this update google Id p unauthorized response has a 5xx status code
func (o *UpdateGoogleIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this update google Id p unauthorized response a status code equal to that given
func (o *UpdateGoogleIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *UpdateGoogleIDPUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/google/{iid}][%d] updateGoogleIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *UpdateGoogleIDPUnauthorized) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/google/{iid}][%d] updateGoogleIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *UpdateGoogleIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateGoogleIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateGoogleIDPForbidden creates a UpdateGoogleIDPForbidden with default headers values
func NewUpdateGoogleIDPForbidden() *UpdateGoogleIDPForbidden {
	return &UpdateGoogleIDPForbidden{}
}

/*
UpdateGoogleIDPForbidden describes a response with status code 403, with default header values.

HttpError
*/
type UpdateGoogleIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this update google Id p forbidden response has a 2xx status code
func (o *UpdateGoogleIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update google Id p forbidden response has a 3xx status code
func (o *UpdateGoogleIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update google Id p forbidden response has a 4xx status code
func (o *UpdateGoogleIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update google Id p forbidden response has a 5xx status code
func (o *UpdateGoogleIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update google Id p forbidden response a status code equal to that given
func (o *UpdateGoogleIDPForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *UpdateGoogleIDPForbidden) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/google/{iid}][%d] updateGoogleIdPForbidden  %+v", 403, o.Payload)
}

func (o *UpdateGoogleIDPForbidden) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/google/{iid}][%d] updateGoogleIdPForbidden  %+v", 403, o.Payload)
}

func (o *UpdateGoogleIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateGoogleIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateGoogleIDPNotFound creates a UpdateGoogleIDPNotFound with default headers values
func NewUpdateGoogleIDPNotFound() *UpdateGoogleIDPNotFound {
	return &UpdateGoogleIDPNotFound{}
}

/*
UpdateGoogleIDPNotFound describes a response with status code 404, with default header values.

HttpError
*/
type UpdateGoogleIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this update google Id p not found response has a 2xx status code
func (o *UpdateGoogleIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update google Id p not found response has a 3xx status code
func (o *UpdateGoogleIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update google Id p not found response has a 4xx status code
func (o *UpdateGoogleIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this update google Id p not found response has a 5xx status code
func (o *UpdateGoogleIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this update google Id p not found response a status code equal to that given
func (o *UpdateGoogleIDPNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *UpdateGoogleIDPNotFound) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/google/{iid}][%d] updateGoogleIdPNotFound  %+v", 404, o.Payload)
}

func (o *UpdateGoogleIDPNotFound) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/google/{iid}][%d] updateGoogleIdPNotFound  %+v", 404, o.Payload)
}

func (o *UpdateGoogleIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateGoogleIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateGoogleIDPUnprocessableEntity creates a UpdateGoogleIDPUnprocessableEntity with default headers values
func NewUpdateGoogleIDPUnprocessableEntity() *UpdateGoogleIDPUnprocessableEntity {
	return &UpdateGoogleIDPUnprocessableEntity{}
}

/*
UpdateGoogleIDPUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type UpdateGoogleIDPUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this update google Id p unprocessable entity response has a 2xx status code
func (o *UpdateGoogleIDPUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update google Id p unprocessable entity response has a 3xx status code
func (o *UpdateGoogleIDPUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update google Id p unprocessable entity response has a 4xx status code
func (o *UpdateGoogleIDPUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this update google Id p unprocessable entity response has a 5xx status code
func (o *UpdateGoogleIDPUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this update google Id p unprocessable entity response a status code equal to that given
func (o *UpdateGoogleIDPUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

func (o *UpdateGoogleIDPUnprocessableEntity) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/google/{iid}][%d] updateGoogleIdPUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *UpdateGoogleIDPUnprocessableEntity) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/google/{iid}][%d] updateGoogleIdPUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *UpdateGoogleIDPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateGoogleIDPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateGoogleIDPTooManyRequests creates a UpdateGoogleIDPTooManyRequests with default headers values
func NewUpdateGoogleIDPTooManyRequests() *UpdateGoogleIDPTooManyRequests {
	return &UpdateGoogleIDPTooManyRequests{}
}

/*
UpdateGoogleIDPTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type UpdateGoogleIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this update google Id p too many requests response has a 2xx status code
func (o *UpdateGoogleIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update google Id p too many requests response has a 3xx status code
func (o *UpdateGoogleIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update google Id p too many requests response has a 4xx status code
func (o *UpdateGoogleIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update google Id p too many requests response has a 5xx status code
func (o *UpdateGoogleIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update google Id p too many requests response a status code equal to that given
func (o *UpdateGoogleIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *UpdateGoogleIDPTooManyRequests) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/google/{iid}][%d] updateGoogleIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateGoogleIDPTooManyRequests) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}/idps/google/{iid}][%d] updateGoogleIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateGoogleIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateGoogleIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
