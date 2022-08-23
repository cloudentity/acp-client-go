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

// VerifyOTPReader is a Reader for the VerifyOTP structure.
type VerifyOTPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *VerifyOTPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewVerifyOTPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewVerifyOTPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewVerifyOTPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewVerifyOTPOK creates a VerifyOTPOK with default headers values
func NewVerifyOTPOK() *VerifyOTPOK {
	return &VerifyOTPOK{}
}

/* VerifyOTPOK describes a response with status code 200, with default header values.

User
*/
type VerifyOTPOK struct {
	Payload *models.UserID
}

func (o *VerifyOTPOK) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/otp/verify][%d] verifyOTPOK  %+v", 200, o.Payload)
}
func (o *VerifyOTPOK) GetPayload() *models.UserID {
	return o.Payload
}

func (o *VerifyOTPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.UserID)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewVerifyOTPUnauthorized creates a VerifyOTPUnauthorized with default headers values
func NewVerifyOTPUnauthorized() *VerifyOTPUnauthorized {
	return &VerifyOTPUnauthorized{}
}

/* VerifyOTPUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type VerifyOTPUnauthorized struct {
	Payload *models.Error
}

func (o *VerifyOTPUnauthorized) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/otp/verify][%d] verifyOTPUnauthorized  %+v", 401, o.Payload)
}
func (o *VerifyOTPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *VerifyOTPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewVerifyOTPUnprocessableEntity creates a VerifyOTPUnprocessableEntity with default headers values
func NewVerifyOTPUnprocessableEntity() *VerifyOTPUnprocessableEntity {
	return &VerifyOTPUnprocessableEntity{}
}

/* VerifyOTPUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type VerifyOTPUnprocessableEntity struct {
	Payload *models.Error
}

func (o *VerifyOTPUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/otp/verify][%d] verifyOTPUnprocessableEntity  %+v", 422, o.Payload)
}
func (o *VerifyOTPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *VerifyOTPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
