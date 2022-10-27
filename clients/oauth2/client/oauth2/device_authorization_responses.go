// Code generated by go-swagger; DO NOT EDIT.

package oauth2

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/oauth2/models"
)

// DeviceAuthorizationReader is a Reader for the DeviceAuthorization structure.
type DeviceAuthorizationReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeviceAuthorizationReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDeviceAuthorizationOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDeviceAuthorizationBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewDeviceAuthorizationUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewDeviceAuthorizationMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 413:
		result := NewDeviceAuthorizationRequestEntityTooLarge()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewDeviceAuthorizationTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewDeviceAuthorizationOK creates a DeviceAuthorizationOK with default headers values
func NewDeviceAuthorizationOK() *DeviceAuthorizationOK {
	return &DeviceAuthorizationOK{}
}

/*
DeviceAuthorizationOK describes a response with status code 200, with default header values.

Device Authorization Response
*/
type DeviceAuthorizationOK struct {
	Payload *models.DeviceResponse
}

// IsSuccess returns true when this device authorization o k response has a 2xx status code
func (o *DeviceAuthorizationOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this device authorization o k response has a 3xx status code
func (o *DeviceAuthorizationOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this device authorization o k response has a 4xx status code
func (o *DeviceAuthorizationOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this device authorization o k response has a 5xx status code
func (o *DeviceAuthorizationOK) IsServerError() bool {
	return false
}

// IsCode returns true when this device authorization o k response a status code equal to that given
func (o *DeviceAuthorizationOK) IsCode(code int) bool {
	return code == 200
}

func (o *DeviceAuthorizationOK) Error() string {
	return fmt.Sprintf("[POST /device/authorization][%d] deviceAuthorizationOK  %+v", 200, o.Payload)
}

func (o *DeviceAuthorizationOK) String() string {
	return fmt.Sprintf("[POST /device/authorization][%d] deviceAuthorizationOK  %+v", 200, o.Payload)
}

func (o *DeviceAuthorizationOK) GetPayload() *models.DeviceResponse {
	return o.Payload
}

func (o *DeviceAuthorizationOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.DeviceResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeviceAuthorizationBadRequest creates a DeviceAuthorizationBadRequest with default headers values
func NewDeviceAuthorizationBadRequest() *DeviceAuthorizationBadRequest {
	return &DeviceAuthorizationBadRequest{}
}

/*
DeviceAuthorizationBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type DeviceAuthorizationBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this device authorization bad request response has a 2xx status code
func (o *DeviceAuthorizationBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this device authorization bad request response has a 3xx status code
func (o *DeviceAuthorizationBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this device authorization bad request response has a 4xx status code
func (o *DeviceAuthorizationBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this device authorization bad request response has a 5xx status code
func (o *DeviceAuthorizationBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this device authorization bad request response a status code equal to that given
func (o *DeviceAuthorizationBadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *DeviceAuthorizationBadRequest) Error() string {
	return fmt.Sprintf("[POST /device/authorization][%d] deviceAuthorizationBadRequest  %+v", 400, o.Payload)
}

func (o *DeviceAuthorizationBadRequest) String() string {
	return fmt.Sprintf("[POST /device/authorization][%d] deviceAuthorizationBadRequest  %+v", 400, o.Payload)
}

func (o *DeviceAuthorizationBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeviceAuthorizationBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeviceAuthorizationUnauthorized creates a DeviceAuthorizationUnauthorized with default headers values
func NewDeviceAuthorizationUnauthorized() *DeviceAuthorizationUnauthorized {
	return &DeviceAuthorizationUnauthorized{}
}

/*
DeviceAuthorizationUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type DeviceAuthorizationUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this device authorization unauthorized response has a 2xx status code
func (o *DeviceAuthorizationUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this device authorization unauthorized response has a 3xx status code
func (o *DeviceAuthorizationUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this device authorization unauthorized response has a 4xx status code
func (o *DeviceAuthorizationUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this device authorization unauthorized response has a 5xx status code
func (o *DeviceAuthorizationUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this device authorization unauthorized response a status code equal to that given
func (o *DeviceAuthorizationUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *DeviceAuthorizationUnauthorized) Error() string {
	return fmt.Sprintf("[POST /device/authorization][%d] deviceAuthorizationUnauthorized  %+v", 401, o.Payload)
}

func (o *DeviceAuthorizationUnauthorized) String() string {
	return fmt.Sprintf("[POST /device/authorization][%d] deviceAuthorizationUnauthorized  %+v", 401, o.Payload)
}

func (o *DeviceAuthorizationUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeviceAuthorizationUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeviceAuthorizationMethodNotAllowed creates a DeviceAuthorizationMethodNotAllowed with default headers values
func NewDeviceAuthorizationMethodNotAllowed() *DeviceAuthorizationMethodNotAllowed {
	return &DeviceAuthorizationMethodNotAllowed{}
}

/*
DeviceAuthorizationMethodNotAllowed describes a response with status code 405, with default header values.

HttpError
*/
type DeviceAuthorizationMethodNotAllowed struct {
	Payload *models.Error
}

// IsSuccess returns true when this device authorization method not allowed response has a 2xx status code
func (o *DeviceAuthorizationMethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this device authorization method not allowed response has a 3xx status code
func (o *DeviceAuthorizationMethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this device authorization method not allowed response has a 4xx status code
func (o *DeviceAuthorizationMethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this device authorization method not allowed response has a 5xx status code
func (o *DeviceAuthorizationMethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this device authorization method not allowed response a status code equal to that given
func (o *DeviceAuthorizationMethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

func (o *DeviceAuthorizationMethodNotAllowed) Error() string {
	return fmt.Sprintf("[POST /device/authorization][%d] deviceAuthorizationMethodNotAllowed  %+v", 405, o.Payload)
}

func (o *DeviceAuthorizationMethodNotAllowed) String() string {
	return fmt.Sprintf("[POST /device/authorization][%d] deviceAuthorizationMethodNotAllowed  %+v", 405, o.Payload)
}

func (o *DeviceAuthorizationMethodNotAllowed) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeviceAuthorizationMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeviceAuthorizationRequestEntityTooLarge creates a DeviceAuthorizationRequestEntityTooLarge with default headers values
func NewDeviceAuthorizationRequestEntityTooLarge() *DeviceAuthorizationRequestEntityTooLarge {
	return &DeviceAuthorizationRequestEntityTooLarge{}
}

/*
DeviceAuthorizationRequestEntityTooLarge describes a response with status code 413, with default header values.

HttpError
*/
type DeviceAuthorizationRequestEntityTooLarge struct {
	Payload *models.Error
}

// IsSuccess returns true when this device authorization request entity too large response has a 2xx status code
func (o *DeviceAuthorizationRequestEntityTooLarge) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this device authorization request entity too large response has a 3xx status code
func (o *DeviceAuthorizationRequestEntityTooLarge) IsRedirect() bool {
	return false
}

// IsClientError returns true when this device authorization request entity too large response has a 4xx status code
func (o *DeviceAuthorizationRequestEntityTooLarge) IsClientError() bool {
	return true
}

// IsServerError returns true when this device authorization request entity too large response has a 5xx status code
func (o *DeviceAuthorizationRequestEntityTooLarge) IsServerError() bool {
	return false
}

// IsCode returns true when this device authorization request entity too large response a status code equal to that given
func (o *DeviceAuthorizationRequestEntityTooLarge) IsCode(code int) bool {
	return code == 413
}

func (o *DeviceAuthorizationRequestEntityTooLarge) Error() string {
	return fmt.Sprintf("[POST /device/authorization][%d] deviceAuthorizationRequestEntityTooLarge  %+v", 413, o.Payload)
}

func (o *DeviceAuthorizationRequestEntityTooLarge) String() string {
	return fmt.Sprintf("[POST /device/authorization][%d] deviceAuthorizationRequestEntityTooLarge  %+v", 413, o.Payload)
}

func (o *DeviceAuthorizationRequestEntityTooLarge) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeviceAuthorizationRequestEntityTooLarge) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeviceAuthorizationTooManyRequests creates a DeviceAuthorizationTooManyRequests with default headers values
func NewDeviceAuthorizationTooManyRequests() *DeviceAuthorizationTooManyRequests {
	return &DeviceAuthorizationTooManyRequests{}
}

/*
DeviceAuthorizationTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type DeviceAuthorizationTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this device authorization too many requests response has a 2xx status code
func (o *DeviceAuthorizationTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this device authorization too many requests response has a 3xx status code
func (o *DeviceAuthorizationTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this device authorization too many requests response has a 4xx status code
func (o *DeviceAuthorizationTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this device authorization too many requests response has a 5xx status code
func (o *DeviceAuthorizationTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this device authorization too many requests response a status code equal to that given
func (o *DeviceAuthorizationTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *DeviceAuthorizationTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /device/authorization][%d] deviceAuthorizationTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeviceAuthorizationTooManyRequests) String() string {
	return fmt.Sprintf("[POST /device/authorization][%d] deviceAuthorizationTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeviceAuthorizationTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeviceAuthorizationTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
