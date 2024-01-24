// Code generated by go-swagger; DO NOT EDIT.

package o_b_u_k

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"fmt"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/cloudentity/acp-client-go/clients/obuk/models"
)

// OpenbankingAccountAccessConsentIntrospectReader is a Reader for the OpenbankingAccountAccessConsentIntrospect structure.
type OpenbankingAccountAccessConsentIntrospectReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *OpenbankingAccountAccessConsentIntrospectReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewOpenbankingAccountAccessConsentIntrospectOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewOpenbankingAccountAccessConsentIntrospectUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewOpenbankingAccountAccessConsentIntrospectNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewOpenbankingAccountAccessConsentIntrospectTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /open-banking/v3.1/aisp/account-access-consents/introspect] openbankingAccountAccessConsentIntrospect", response, response.Code())
	}
}

// NewOpenbankingAccountAccessConsentIntrospectOK creates a OpenbankingAccountAccessConsentIntrospectOK with default headers values
func NewOpenbankingAccountAccessConsentIntrospectOK() *OpenbankingAccountAccessConsentIntrospectOK {
	return &OpenbankingAccountAccessConsentIntrospectOK{}
}

/*
OpenbankingAccountAccessConsentIntrospectOK describes a response with status code 200, with default header values.

Introspect Openbanking Account Access Consent Response
*/
type OpenbankingAccountAccessConsentIntrospectOK struct {
	Payload *OpenbankingAccountAccessConsentIntrospectOKBody
}

// IsSuccess returns true when this openbanking account access consent introspect o k response has a 2xx status code
func (o *OpenbankingAccountAccessConsentIntrospectOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this openbanking account access consent introspect o k response has a 3xx status code
func (o *OpenbankingAccountAccessConsentIntrospectOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this openbanking account access consent introspect o k response has a 4xx status code
func (o *OpenbankingAccountAccessConsentIntrospectOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this openbanking account access consent introspect o k response has a 5xx status code
func (o *OpenbankingAccountAccessConsentIntrospectOK) IsServerError() bool {
	return false
}

// IsCode returns true when this openbanking account access consent introspect o k response a status code equal to that given
func (o *OpenbankingAccountAccessConsentIntrospectOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the openbanking account access consent introspect o k response
func (o *OpenbankingAccountAccessConsentIntrospectOK) Code() int {
	return 200
}

func (o *OpenbankingAccountAccessConsentIntrospectOK) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/aisp/account-access-consents/introspect][%d] openbankingAccountAccessConsentIntrospectOK  %+v", 200, o.Payload)
}

func (o *OpenbankingAccountAccessConsentIntrospectOK) String() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/aisp/account-access-consents/introspect][%d] openbankingAccountAccessConsentIntrospectOK  %+v", 200, o.Payload)
}

func (o *OpenbankingAccountAccessConsentIntrospectOK) GetPayload() *OpenbankingAccountAccessConsentIntrospectOKBody {
	return o.Payload
}

func (o *OpenbankingAccountAccessConsentIntrospectOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(OpenbankingAccountAccessConsentIntrospectOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewOpenbankingAccountAccessConsentIntrospectUnauthorized creates a OpenbankingAccountAccessConsentIntrospectUnauthorized with default headers values
func NewOpenbankingAccountAccessConsentIntrospectUnauthorized() *OpenbankingAccountAccessConsentIntrospectUnauthorized {
	return &OpenbankingAccountAccessConsentIntrospectUnauthorized{}
}

/*
OpenbankingAccountAccessConsentIntrospectUnauthorized describes a response with status code 401, with default header values.

ErrorResponse
*/
type OpenbankingAccountAccessConsentIntrospectUnauthorized struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this openbanking account access consent introspect unauthorized response has a 2xx status code
func (o *OpenbankingAccountAccessConsentIntrospectUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this openbanking account access consent introspect unauthorized response has a 3xx status code
func (o *OpenbankingAccountAccessConsentIntrospectUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this openbanking account access consent introspect unauthorized response has a 4xx status code
func (o *OpenbankingAccountAccessConsentIntrospectUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this openbanking account access consent introspect unauthorized response has a 5xx status code
func (o *OpenbankingAccountAccessConsentIntrospectUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this openbanking account access consent introspect unauthorized response a status code equal to that given
func (o *OpenbankingAccountAccessConsentIntrospectUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the openbanking account access consent introspect unauthorized response
func (o *OpenbankingAccountAccessConsentIntrospectUnauthorized) Code() int {
	return 401
}

func (o *OpenbankingAccountAccessConsentIntrospectUnauthorized) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/aisp/account-access-consents/introspect][%d] openbankingAccountAccessConsentIntrospectUnauthorized  %+v", 401, o.Payload)
}

func (o *OpenbankingAccountAccessConsentIntrospectUnauthorized) String() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/aisp/account-access-consents/introspect][%d] openbankingAccountAccessConsentIntrospectUnauthorized  %+v", 401, o.Payload)
}

func (o *OpenbankingAccountAccessConsentIntrospectUnauthorized) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *OpenbankingAccountAccessConsentIntrospectUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewOpenbankingAccountAccessConsentIntrospectNotFound creates a OpenbankingAccountAccessConsentIntrospectNotFound with default headers values
func NewOpenbankingAccountAccessConsentIntrospectNotFound() *OpenbankingAccountAccessConsentIntrospectNotFound {
	return &OpenbankingAccountAccessConsentIntrospectNotFound{}
}

/*
OpenbankingAccountAccessConsentIntrospectNotFound describes a response with status code 404, with default header values.

ErrorResponse
*/
type OpenbankingAccountAccessConsentIntrospectNotFound struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this openbanking account access consent introspect not found response has a 2xx status code
func (o *OpenbankingAccountAccessConsentIntrospectNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this openbanking account access consent introspect not found response has a 3xx status code
func (o *OpenbankingAccountAccessConsentIntrospectNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this openbanking account access consent introspect not found response has a 4xx status code
func (o *OpenbankingAccountAccessConsentIntrospectNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this openbanking account access consent introspect not found response has a 5xx status code
func (o *OpenbankingAccountAccessConsentIntrospectNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this openbanking account access consent introspect not found response a status code equal to that given
func (o *OpenbankingAccountAccessConsentIntrospectNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the openbanking account access consent introspect not found response
func (o *OpenbankingAccountAccessConsentIntrospectNotFound) Code() int {
	return 404
}

func (o *OpenbankingAccountAccessConsentIntrospectNotFound) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/aisp/account-access-consents/introspect][%d] openbankingAccountAccessConsentIntrospectNotFound  %+v", 404, o.Payload)
}

func (o *OpenbankingAccountAccessConsentIntrospectNotFound) String() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/aisp/account-access-consents/introspect][%d] openbankingAccountAccessConsentIntrospectNotFound  %+v", 404, o.Payload)
}

func (o *OpenbankingAccountAccessConsentIntrospectNotFound) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *OpenbankingAccountAccessConsentIntrospectNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewOpenbankingAccountAccessConsentIntrospectTooManyRequests creates a OpenbankingAccountAccessConsentIntrospectTooManyRequests with default headers values
func NewOpenbankingAccountAccessConsentIntrospectTooManyRequests() *OpenbankingAccountAccessConsentIntrospectTooManyRequests {
	return &OpenbankingAccountAccessConsentIntrospectTooManyRequests{}
}

/*
OpenbankingAccountAccessConsentIntrospectTooManyRequests describes a response with status code 429, with default header values.

ErrorResponse
*/
type OpenbankingAccountAccessConsentIntrospectTooManyRequests struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this openbanking account access consent introspect too many requests response has a 2xx status code
func (o *OpenbankingAccountAccessConsentIntrospectTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this openbanking account access consent introspect too many requests response has a 3xx status code
func (o *OpenbankingAccountAccessConsentIntrospectTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this openbanking account access consent introspect too many requests response has a 4xx status code
func (o *OpenbankingAccountAccessConsentIntrospectTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this openbanking account access consent introspect too many requests response has a 5xx status code
func (o *OpenbankingAccountAccessConsentIntrospectTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this openbanking account access consent introspect too many requests response a status code equal to that given
func (o *OpenbankingAccountAccessConsentIntrospectTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the openbanking account access consent introspect too many requests response
func (o *OpenbankingAccountAccessConsentIntrospectTooManyRequests) Code() int {
	return 429
}

func (o *OpenbankingAccountAccessConsentIntrospectTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/aisp/account-access-consents/introspect][%d] openbankingAccountAccessConsentIntrospectTooManyRequests  %+v", 429, o.Payload)
}

func (o *OpenbankingAccountAccessConsentIntrospectTooManyRequests) String() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/aisp/account-access-consents/introspect][%d] openbankingAccountAccessConsentIntrospectTooManyRequests  %+v", 429, o.Payload)
}

func (o *OpenbankingAccountAccessConsentIntrospectTooManyRequests) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *OpenbankingAccountAccessConsentIntrospectTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*
OpenbankingAccountAccessConsentIntrospectOKBody openbanking account access consent introspect o k body
swagger:model OpenbankingAccountAccessConsentIntrospectOKBody
*/
type OpenbankingAccountAccessConsentIntrospectOKBody struct {
	models.IntrospectResponse

	models.AccountAccessConsent

	// account i ds
	AccountIDs []string `json:"AccountIDs" yaml:"AccountIDs"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (o *OpenbankingAccountAccessConsentIntrospectOKBody) UnmarshalJSON(raw []byte) error {
	// OpenbankingAccountAccessConsentIntrospectOKBodyAO0
	var openbankingAccountAccessConsentIntrospectOKBodyAO0 models.IntrospectResponse
	if err := swag.ReadJSON(raw, &openbankingAccountAccessConsentIntrospectOKBodyAO0); err != nil {
		return err
	}
	o.IntrospectResponse = openbankingAccountAccessConsentIntrospectOKBodyAO0

	// OpenbankingAccountAccessConsentIntrospectOKBodyAO1
	var openbankingAccountAccessConsentIntrospectOKBodyAO1 models.AccountAccessConsent
	if err := swag.ReadJSON(raw, &openbankingAccountAccessConsentIntrospectOKBodyAO1); err != nil {
		return err
	}
	o.AccountAccessConsent = openbankingAccountAccessConsentIntrospectOKBodyAO1

	// OpenbankingAccountAccessConsentIntrospectOKBodyAO2
	var dataOpenbankingAccountAccessConsentIntrospectOKBodyAO2 struct {
		AccountIDs []string `json:"AccountIDs"`
	}
	if err := swag.ReadJSON(raw, &dataOpenbankingAccountAccessConsentIntrospectOKBodyAO2); err != nil {
		return err
	}

	o.AccountIDs = dataOpenbankingAccountAccessConsentIntrospectOKBodyAO2.AccountIDs

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (o OpenbankingAccountAccessConsentIntrospectOKBody) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 3)

	openbankingAccountAccessConsentIntrospectOKBodyAO0, err := swag.WriteJSON(o.IntrospectResponse)
	if err != nil {
		return nil, err
	}
	_parts = append(_parts, openbankingAccountAccessConsentIntrospectOKBodyAO0)

	openbankingAccountAccessConsentIntrospectOKBodyAO1, err := swag.WriteJSON(o.AccountAccessConsent)
	if err != nil {
		return nil, err
	}
	_parts = append(_parts, openbankingAccountAccessConsentIntrospectOKBodyAO1)
	var dataOpenbankingAccountAccessConsentIntrospectOKBodyAO2 struct {
		AccountIDs []string `json:"AccountIDs"`
	}

	dataOpenbankingAccountAccessConsentIntrospectOKBodyAO2.AccountIDs = o.AccountIDs

	jsonDataOpenbankingAccountAccessConsentIntrospectOKBodyAO2, errOpenbankingAccountAccessConsentIntrospectOKBodyAO2 := swag.WriteJSON(dataOpenbankingAccountAccessConsentIntrospectOKBodyAO2)
	if errOpenbankingAccountAccessConsentIntrospectOKBodyAO2 != nil {
		return nil, errOpenbankingAccountAccessConsentIntrospectOKBodyAO2
	}
	_parts = append(_parts, jsonDataOpenbankingAccountAccessConsentIntrospectOKBodyAO2)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this openbanking account access consent introspect o k body
func (o *OpenbankingAccountAccessConsentIntrospectOKBody) Validate(formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with models.IntrospectResponse
	if err := o.IntrospectResponse.Validate(formats); err != nil {
		res = append(res, err)
	}
	// validation for a type composition with models.AccountAccessConsent
	if err := o.AccountAccessConsent.Validate(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validate this openbanking account access consent introspect o k body based on the context it is used
func (o *OpenbankingAccountAccessConsentIntrospectOKBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with models.IntrospectResponse
	if err := o.IntrospectResponse.ContextValidate(ctx, formats); err != nil {
		res = append(res, err)
	}
	// validation for a type composition with models.AccountAccessConsent
	if err := o.AccountAccessConsent.ContextValidate(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// MarshalBinary interface implementation
func (o *OpenbankingAccountAccessConsentIntrospectOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *OpenbankingAccountAccessConsentIntrospectOKBody) UnmarshalBinary(b []byte) error {
	var res OpenbankingAccountAccessConsentIntrospectOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
