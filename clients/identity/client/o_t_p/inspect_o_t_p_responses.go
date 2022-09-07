// Code generated by go-swagger; DO NOT EDIT.

package o_t_p

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identity/models"
)

// InspectOTPReader is a Reader for the InspectOTP structure.
type InspectOTPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *InspectOTPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewInspectOTPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewInspectOTPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewInspectOTPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewInspectOTPOK creates a InspectOTPOK with default headers values
func NewInspectOTPOK() *InspectOTPOK {
	return &InspectOTPOK{}
}

/* InspectOTPOK describes a response with status code 200, with default header values.

OTP
*/
type InspectOTPOK struct {
	Payload *models.InspectOTPUserOperationalData
}

func (o *InspectOTPOK) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/otp/inspect][%d] inspectOTPOK  %+v", 200, o.Payload)
}
func (o *InspectOTPOK) GetPayload() *models.InspectOTPUserOperationalData {
	return o.Payload
}

func (o *InspectOTPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.InspectOTPUserOperationalData)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewInspectOTPUnauthorized creates a InspectOTPUnauthorized with default headers values
func NewInspectOTPUnauthorized() *InspectOTPUnauthorized {
	return &InspectOTPUnauthorized{}
}

/* InspectOTPUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type InspectOTPUnauthorized struct {
	Payload *models.Error
}

func (o *InspectOTPUnauthorized) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/otp/inspect][%d] inspectOTPUnauthorized  %+v", 401, o.Payload)
}
func (o *InspectOTPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *InspectOTPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewInspectOTPUnprocessableEntity creates a InspectOTPUnprocessableEntity with default headers values
func NewInspectOTPUnprocessableEntity() *InspectOTPUnprocessableEntity {
	return &InspectOTPUnprocessableEntity{}
}

/* InspectOTPUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type InspectOTPUnprocessableEntity struct {
	Payload *models.Error
}

func (o *InspectOTPUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/otp/inspect][%d] inspectOTPUnprocessableEntity  %+v", 422, o.Payload)
}
func (o *InspectOTPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *InspectOTPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
