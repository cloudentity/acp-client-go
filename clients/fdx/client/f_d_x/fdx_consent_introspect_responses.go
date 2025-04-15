// Code generated by go-swagger; DO NOT EDIT.

package f_d_x

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/cloudentity/acp-client-go/clients/fdx/models"
)

// FdxConsentIntrospectReader is a Reader for the FdxConsentIntrospect structure.
type FdxConsentIntrospectReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *FdxConsentIntrospectReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewFdxConsentIntrospectOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewFdxConsentIntrospectUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewFdxConsentIntrospectNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewFdxConsentIntrospectTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /fdx/consents/introspect] fdxConsentIntrospect", response, response.Code())
	}
}

// NewFdxConsentIntrospectOK creates a FdxConsentIntrospectOK with default headers values
func NewFdxConsentIntrospectOK() *FdxConsentIntrospectOK {
	return &FdxConsentIntrospectOK{}
}

/*
FdxConsentIntrospectOK describes a response with status code 200, with default header values.

Introspect FDX Consent Response
*/
type FdxConsentIntrospectOK struct {
	Payload *FdxConsentIntrospectOKBody
}

// IsSuccess returns true when this fdx consent introspect o k response has a 2xx status code
func (o *FdxConsentIntrospectOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this fdx consent introspect o k response has a 3xx status code
func (o *FdxConsentIntrospectOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this fdx consent introspect o k response has a 4xx status code
func (o *FdxConsentIntrospectOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this fdx consent introspect o k response has a 5xx status code
func (o *FdxConsentIntrospectOK) IsServerError() bool {
	return false
}

// IsCode returns true when this fdx consent introspect o k response a status code equal to that given
func (o *FdxConsentIntrospectOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the fdx consent introspect o k response
func (o *FdxConsentIntrospectOK) Code() int {
	return 200
}

func (o *FdxConsentIntrospectOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /fdx/consents/introspect][%d] fdxConsentIntrospectOK %s", 200, payload)
}

func (o *FdxConsentIntrospectOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /fdx/consents/introspect][%d] fdxConsentIntrospectOK %s", 200, payload)
}

func (o *FdxConsentIntrospectOK) GetPayload() *FdxConsentIntrospectOKBody {
	return o.Payload
}

func (o *FdxConsentIntrospectOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(FdxConsentIntrospectOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewFdxConsentIntrospectUnauthorized creates a FdxConsentIntrospectUnauthorized with default headers values
func NewFdxConsentIntrospectUnauthorized() *FdxConsentIntrospectUnauthorized {
	return &FdxConsentIntrospectUnauthorized{}
}

/*
FdxConsentIntrospectUnauthorized describes a response with status code 401, with default header values.

ErrorResponse
*/
type FdxConsentIntrospectUnauthorized struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this fdx consent introspect unauthorized response has a 2xx status code
func (o *FdxConsentIntrospectUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this fdx consent introspect unauthorized response has a 3xx status code
func (o *FdxConsentIntrospectUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this fdx consent introspect unauthorized response has a 4xx status code
func (o *FdxConsentIntrospectUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this fdx consent introspect unauthorized response has a 5xx status code
func (o *FdxConsentIntrospectUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this fdx consent introspect unauthorized response a status code equal to that given
func (o *FdxConsentIntrospectUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the fdx consent introspect unauthorized response
func (o *FdxConsentIntrospectUnauthorized) Code() int {
	return 401
}

func (o *FdxConsentIntrospectUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /fdx/consents/introspect][%d] fdxConsentIntrospectUnauthorized %s", 401, payload)
}

func (o *FdxConsentIntrospectUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /fdx/consents/introspect][%d] fdxConsentIntrospectUnauthorized %s", 401, payload)
}

func (o *FdxConsentIntrospectUnauthorized) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *FdxConsentIntrospectUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewFdxConsentIntrospectNotFound creates a FdxConsentIntrospectNotFound with default headers values
func NewFdxConsentIntrospectNotFound() *FdxConsentIntrospectNotFound {
	return &FdxConsentIntrospectNotFound{}
}

/*
FdxConsentIntrospectNotFound describes a response with status code 404, with default header values.

ErrorResponse
*/
type FdxConsentIntrospectNotFound struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this fdx consent introspect not found response has a 2xx status code
func (o *FdxConsentIntrospectNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this fdx consent introspect not found response has a 3xx status code
func (o *FdxConsentIntrospectNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this fdx consent introspect not found response has a 4xx status code
func (o *FdxConsentIntrospectNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this fdx consent introspect not found response has a 5xx status code
func (o *FdxConsentIntrospectNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this fdx consent introspect not found response a status code equal to that given
func (o *FdxConsentIntrospectNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the fdx consent introspect not found response
func (o *FdxConsentIntrospectNotFound) Code() int {
	return 404
}

func (o *FdxConsentIntrospectNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /fdx/consents/introspect][%d] fdxConsentIntrospectNotFound %s", 404, payload)
}

func (o *FdxConsentIntrospectNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /fdx/consents/introspect][%d] fdxConsentIntrospectNotFound %s", 404, payload)
}

func (o *FdxConsentIntrospectNotFound) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *FdxConsentIntrospectNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewFdxConsentIntrospectTooManyRequests creates a FdxConsentIntrospectTooManyRequests with default headers values
func NewFdxConsentIntrospectTooManyRequests() *FdxConsentIntrospectTooManyRequests {
	return &FdxConsentIntrospectTooManyRequests{}
}

/*
FdxConsentIntrospectTooManyRequests describes a response with status code 429, with default header values.

ErrorResponse
*/
type FdxConsentIntrospectTooManyRequests struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this fdx consent introspect too many requests response has a 2xx status code
func (o *FdxConsentIntrospectTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this fdx consent introspect too many requests response has a 3xx status code
func (o *FdxConsentIntrospectTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this fdx consent introspect too many requests response has a 4xx status code
func (o *FdxConsentIntrospectTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this fdx consent introspect too many requests response has a 5xx status code
func (o *FdxConsentIntrospectTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this fdx consent introspect too many requests response a status code equal to that given
func (o *FdxConsentIntrospectTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the fdx consent introspect too many requests response
func (o *FdxConsentIntrospectTooManyRequests) Code() int {
	return 429
}

func (o *FdxConsentIntrospectTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /fdx/consents/introspect][%d] fdxConsentIntrospectTooManyRequests %s", 429, payload)
}

func (o *FdxConsentIntrospectTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /fdx/consents/introspect][%d] fdxConsentIntrospectTooManyRequests %s", 429, payload)
}

func (o *FdxConsentIntrospectTooManyRequests) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *FdxConsentIntrospectTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*
FdxConsentIntrospectOKBody fdx consent introspect o k body
swagger:model FdxConsentIntrospectOKBody
*/
type FdxConsentIntrospectOKBody struct {
	models.IntrospectResponse

	// fdx consent
	FdxConsent *models.GetFDXConsent `json:"fdx_consent,omitempty" yaml:"fdx_consent,omitempty"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (o *FdxConsentIntrospectOKBody) UnmarshalJSON(raw []byte) error {
	// FdxConsentIntrospectOKBodyAO0
	var fdxConsentIntrospectOKBodyAO0 models.IntrospectResponse
	if err := swag.ReadJSON(raw, &fdxConsentIntrospectOKBodyAO0); err != nil {
		return err
	}
	o.IntrospectResponse = fdxConsentIntrospectOKBodyAO0

	// FdxConsentIntrospectOKBodyAO1
	var dataFdxConsentIntrospectOKBodyAO1 struct {
		FdxConsent *models.GetFDXConsent `json:"fdx_consent,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataFdxConsentIntrospectOKBodyAO1); err != nil {
		return err
	}

	o.FdxConsent = dataFdxConsentIntrospectOKBodyAO1.FdxConsent

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (o FdxConsentIntrospectOKBody) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	fdxConsentIntrospectOKBodyAO0, err := swag.WriteJSON(o.IntrospectResponse)
	if err != nil {
		return nil, err
	}
	_parts = append(_parts, fdxConsentIntrospectOKBodyAO0)
	var dataFdxConsentIntrospectOKBodyAO1 struct {
		FdxConsent *models.GetFDXConsent `json:"fdx_consent,omitempty"`
	}

	dataFdxConsentIntrospectOKBodyAO1.FdxConsent = o.FdxConsent

	jsonDataFdxConsentIntrospectOKBodyAO1, errFdxConsentIntrospectOKBodyAO1 := swag.WriteJSON(dataFdxConsentIntrospectOKBodyAO1)
	if errFdxConsentIntrospectOKBodyAO1 != nil {
		return nil, errFdxConsentIntrospectOKBodyAO1
	}
	_parts = append(_parts, jsonDataFdxConsentIntrospectOKBodyAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this fdx consent introspect o k body
func (o *FdxConsentIntrospectOKBody) Validate(formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with models.IntrospectResponse
	if err := o.IntrospectResponse.Validate(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateFdxConsent(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *FdxConsentIntrospectOKBody) validateFdxConsent(formats strfmt.Registry) error {

	if swag.IsZero(o.FdxConsent) { // not required
		return nil
	}

	if o.FdxConsent != nil {
		if err := o.FdxConsent.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("fdxConsentIntrospectOK" + "." + "fdx_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("fdxConsentIntrospectOK" + "." + "fdx_consent")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this fdx consent introspect o k body based on the context it is used
func (o *FdxConsentIntrospectOKBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with models.IntrospectResponse
	if err := o.IntrospectResponse.ContextValidate(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := o.contextValidateFdxConsent(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *FdxConsentIntrospectOKBody) contextValidateFdxConsent(ctx context.Context, formats strfmt.Registry) error {

	if o.FdxConsent != nil {

		if swag.IsZero(o.FdxConsent) { // not required
			return nil
		}

		if err := o.FdxConsent.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("fdxConsentIntrospectOK" + "." + "fdx_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("fdxConsentIntrospectOK" + "." + "fdx_consent")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *FdxConsentIntrospectOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *FdxConsentIntrospectOKBody) UnmarshalBinary(b []byte) error {
	var res FdxConsentIntrospectOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
