// Code generated by go-swagger; DO NOT EDIT.

package users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identityself/models"
)

// ResetPasswordConfirmReader is a Reader for the ResetPasswordConfirm structure.
type ResetPasswordConfirmReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ResetPasswordConfirmReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewResetPasswordConfirmNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewResetPasswordConfirmUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewResetPasswordConfirmNoContent creates a ResetPasswordConfirmNoContent with default headers values
func NewResetPasswordConfirmNoContent() *ResetPasswordConfirmNoContent {
	return &ResetPasswordConfirmNoContent{}
}

/* ResetPasswordConfirmNoContent describes a response with status code 204, with default header values.

Password reset
*/
type ResetPasswordConfirmNoContent struct {
}

func (o *ResetPasswordConfirmNoContent) Error() string {
	return fmt.Sprintf("[POST /public/pools/{ipID}/reset-password/confirm][%d] resetPasswordConfirmNoContent ", 204)
}

func (o *ResetPasswordConfirmNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewResetPasswordConfirmUnauthorized creates a ResetPasswordConfirmUnauthorized with default headers values
func NewResetPasswordConfirmUnauthorized() *ResetPasswordConfirmUnauthorized {
	return &ResetPasswordConfirmUnauthorized{}
}

/* ResetPasswordConfirmUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type ResetPasswordConfirmUnauthorized struct {
	Payload *models.Error
}

func (o *ResetPasswordConfirmUnauthorized) Error() string {
	return fmt.Sprintf("[POST /public/pools/{ipID}/reset-password/confirm][%d] resetPasswordConfirmUnauthorized  %+v", 401, o.Payload)
}
func (o *ResetPasswordConfirmUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ResetPasswordConfirmUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
