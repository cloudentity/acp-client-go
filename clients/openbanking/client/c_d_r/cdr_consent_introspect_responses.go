// Code generated by go-swagger; DO NOT EDIT.

package c_d_r

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

	"github.com/cloudentity/acp-client-go/clients/openbanking/models"
)

// CdrConsentIntrospectReader is a Reader for the CdrConsentIntrospect structure.
type CdrConsentIntrospectReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CdrConsentIntrospectReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCdrConsentIntrospectOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewCdrConsentIntrospectUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCdrConsentIntrospectNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCdrConsentIntrospectTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewCdrConsentIntrospectOK creates a CdrConsentIntrospectOK with default headers values
func NewCdrConsentIntrospectOK() *CdrConsentIntrospectOK {
	return &CdrConsentIntrospectOK{}
}

/*
CdrConsentIntrospectOK describes a response with status code 200, with default header values.

Introspect CDR Consent Response
*/
type CdrConsentIntrospectOK struct {
	Payload *CdrConsentIntrospectOKBody
}

// IsSuccess returns true when this cdr consent introspect o k response has a 2xx status code
func (o *CdrConsentIntrospectOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this cdr consent introspect o k response has a 3xx status code
func (o *CdrConsentIntrospectOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cdr consent introspect o k response has a 4xx status code
func (o *CdrConsentIntrospectOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this cdr consent introspect o k response has a 5xx status code
func (o *CdrConsentIntrospectOK) IsServerError() bool {
	return false
}

// IsCode returns true when this cdr consent introspect o k response a status code equal to that given
func (o *CdrConsentIntrospectOK) IsCode(code int) bool {
	return code == 200
}

func (o *CdrConsentIntrospectOK) Error() string {
	return fmt.Sprintf("[POST /cdr/consents/introspect][%d] cdrConsentIntrospectOK  %+v", 200, o.Payload)
}

func (o *CdrConsentIntrospectOK) String() string {
	return fmt.Sprintf("[POST /cdr/consents/introspect][%d] cdrConsentIntrospectOK  %+v", 200, o.Payload)
}

func (o *CdrConsentIntrospectOK) GetPayload() *CdrConsentIntrospectOKBody {
	return o.Payload
}

func (o *CdrConsentIntrospectOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(CdrConsentIntrospectOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCdrConsentIntrospectUnauthorized creates a CdrConsentIntrospectUnauthorized with default headers values
func NewCdrConsentIntrospectUnauthorized() *CdrConsentIntrospectUnauthorized {
	return &CdrConsentIntrospectUnauthorized{}
}

/*
CdrConsentIntrospectUnauthorized describes a response with status code 401, with default header values.

ErrorResponse
*/
type CdrConsentIntrospectUnauthorized struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this cdr consent introspect unauthorized response has a 2xx status code
func (o *CdrConsentIntrospectUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this cdr consent introspect unauthorized response has a 3xx status code
func (o *CdrConsentIntrospectUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cdr consent introspect unauthorized response has a 4xx status code
func (o *CdrConsentIntrospectUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this cdr consent introspect unauthorized response has a 5xx status code
func (o *CdrConsentIntrospectUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this cdr consent introspect unauthorized response a status code equal to that given
func (o *CdrConsentIntrospectUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *CdrConsentIntrospectUnauthorized) Error() string {
	return fmt.Sprintf("[POST /cdr/consents/introspect][%d] cdrConsentIntrospectUnauthorized  %+v", 401, o.Payload)
}

func (o *CdrConsentIntrospectUnauthorized) String() string {
	return fmt.Sprintf("[POST /cdr/consents/introspect][%d] cdrConsentIntrospectUnauthorized  %+v", 401, o.Payload)
}

func (o *CdrConsentIntrospectUnauthorized) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *CdrConsentIntrospectUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCdrConsentIntrospectNotFound creates a CdrConsentIntrospectNotFound with default headers values
func NewCdrConsentIntrospectNotFound() *CdrConsentIntrospectNotFound {
	return &CdrConsentIntrospectNotFound{}
}

/*
CdrConsentIntrospectNotFound describes a response with status code 404, with default header values.

ErrorResponse
*/
type CdrConsentIntrospectNotFound struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this cdr consent introspect not found response has a 2xx status code
func (o *CdrConsentIntrospectNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this cdr consent introspect not found response has a 3xx status code
func (o *CdrConsentIntrospectNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cdr consent introspect not found response has a 4xx status code
func (o *CdrConsentIntrospectNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this cdr consent introspect not found response has a 5xx status code
func (o *CdrConsentIntrospectNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this cdr consent introspect not found response a status code equal to that given
func (o *CdrConsentIntrospectNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *CdrConsentIntrospectNotFound) Error() string {
	return fmt.Sprintf("[POST /cdr/consents/introspect][%d] cdrConsentIntrospectNotFound  %+v", 404, o.Payload)
}

func (o *CdrConsentIntrospectNotFound) String() string {
	return fmt.Sprintf("[POST /cdr/consents/introspect][%d] cdrConsentIntrospectNotFound  %+v", 404, o.Payload)
}

func (o *CdrConsentIntrospectNotFound) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *CdrConsentIntrospectNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCdrConsentIntrospectTooManyRequests creates a CdrConsentIntrospectTooManyRequests with default headers values
func NewCdrConsentIntrospectTooManyRequests() *CdrConsentIntrospectTooManyRequests {
	return &CdrConsentIntrospectTooManyRequests{}
}

/*
CdrConsentIntrospectTooManyRequests describes a response with status code 429, with default header values.

ErrorResponse
*/
type CdrConsentIntrospectTooManyRequests struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this cdr consent introspect too many requests response has a 2xx status code
func (o *CdrConsentIntrospectTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this cdr consent introspect too many requests response has a 3xx status code
func (o *CdrConsentIntrospectTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cdr consent introspect too many requests response has a 4xx status code
func (o *CdrConsentIntrospectTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this cdr consent introspect too many requests response has a 5xx status code
func (o *CdrConsentIntrospectTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this cdr consent introspect too many requests response a status code equal to that given
func (o *CdrConsentIntrospectTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *CdrConsentIntrospectTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /cdr/consents/introspect][%d] cdrConsentIntrospectTooManyRequests  %+v", 429, o.Payload)
}

func (o *CdrConsentIntrospectTooManyRequests) String() string {
	return fmt.Sprintf("[POST /cdr/consents/introspect][%d] cdrConsentIntrospectTooManyRequests  %+v", 429, o.Payload)
}

func (o *CdrConsentIntrospectTooManyRequests) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *CdrConsentIntrospectTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*
CdrConsentIntrospectOKBody cdr consent introspect o k body
swagger:model CdrConsentIntrospectOKBody
*/
type CdrConsentIntrospectOKBody struct {
	models.IntrospectResponse

	// Deprecated list of account ids, use account_ids from cdr_arrangement
	AccountIDs []string `json:"AccountIDs"`

	// cdr arrangement
	CdrArrangement *models.CDRArrangement `json:"cdr_arrangement,omitempty"`

	// CDR arrangement id
	CdrArrangementID string `json:"cdr_arrangement_id,omitempty"`

	// cdr register client metadata
	CdrRegisterClientMetadata *models.CDRRegisterClientMetadata `json:"cdr_register_client_metadata,omitempty"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (o *CdrConsentIntrospectOKBody) UnmarshalJSON(raw []byte) error {
	// CdrConsentIntrospectOKBodyAO0
	var cdrConsentIntrospectOKBodyAO0 models.IntrospectResponse
	if err := swag.ReadJSON(raw, &cdrConsentIntrospectOKBodyAO0); err != nil {
		return err
	}
	o.IntrospectResponse = cdrConsentIntrospectOKBodyAO0

	// CdrConsentIntrospectOKBodyAO1
	var dataCdrConsentIntrospectOKBodyAO1 struct {
		AccountIDs []string `json:"AccountIDs"`

		CdrArrangement *models.CDRArrangement `json:"cdr_arrangement,omitempty"`

		CdrArrangementID string `json:"cdr_arrangement_id,omitempty"`

		CdrRegisterClientMetadata *models.CDRRegisterClientMetadata `json:"cdr_register_client_metadata,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataCdrConsentIntrospectOKBodyAO1); err != nil {
		return err
	}

	o.AccountIDs = dataCdrConsentIntrospectOKBodyAO1.AccountIDs

	o.CdrArrangement = dataCdrConsentIntrospectOKBodyAO1.CdrArrangement

	o.CdrArrangementID = dataCdrConsentIntrospectOKBodyAO1.CdrArrangementID

	o.CdrRegisterClientMetadata = dataCdrConsentIntrospectOKBodyAO1.CdrRegisterClientMetadata

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (o CdrConsentIntrospectOKBody) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	cdrConsentIntrospectOKBodyAO0, err := swag.WriteJSON(o.IntrospectResponse)
	if err != nil {
		return nil, err
	}
	_parts = append(_parts, cdrConsentIntrospectOKBodyAO0)
	var dataCdrConsentIntrospectOKBodyAO1 struct {
		AccountIDs []string `json:"AccountIDs"`

		CdrArrangement *models.CDRArrangement `json:"cdr_arrangement,omitempty"`

		CdrArrangementID string `json:"cdr_arrangement_id,omitempty"`

		CdrRegisterClientMetadata *models.CDRRegisterClientMetadata `json:"cdr_register_client_metadata,omitempty"`
	}

	dataCdrConsentIntrospectOKBodyAO1.AccountIDs = o.AccountIDs

	dataCdrConsentIntrospectOKBodyAO1.CdrArrangement = o.CdrArrangement

	dataCdrConsentIntrospectOKBodyAO1.CdrArrangementID = o.CdrArrangementID

	dataCdrConsentIntrospectOKBodyAO1.CdrRegisterClientMetadata = o.CdrRegisterClientMetadata

	jsonDataCdrConsentIntrospectOKBodyAO1, errCdrConsentIntrospectOKBodyAO1 := swag.WriteJSON(dataCdrConsentIntrospectOKBodyAO1)
	if errCdrConsentIntrospectOKBodyAO1 != nil {
		return nil, errCdrConsentIntrospectOKBodyAO1
	}
	_parts = append(_parts, jsonDataCdrConsentIntrospectOKBodyAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this cdr consent introspect o k body
func (o *CdrConsentIntrospectOKBody) Validate(formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with models.IntrospectResponse
	if err := o.IntrospectResponse.Validate(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateCdrArrangement(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateCdrRegisterClientMetadata(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *CdrConsentIntrospectOKBody) validateCdrArrangement(formats strfmt.Registry) error {

	if swag.IsZero(o.CdrArrangement) { // not required
		return nil
	}

	if o.CdrArrangement != nil {
		if err := o.CdrArrangement.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("cdrConsentIntrospectOK" + "." + "cdr_arrangement")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("cdrConsentIntrospectOK" + "." + "cdr_arrangement")
			}
			return err
		}
	}

	return nil
}

func (o *CdrConsentIntrospectOKBody) validateCdrRegisterClientMetadata(formats strfmt.Registry) error {

	if swag.IsZero(o.CdrRegisterClientMetadata) { // not required
		return nil
	}

	if o.CdrRegisterClientMetadata != nil {
		if err := o.CdrRegisterClientMetadata.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("cdrConsentIntrospectOK" + "." + "cdr_register_client_metadata")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("cdrConsentIntrospectOK" + "." + "cdr_register_client_metadata")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this cdr consent introspect o k body based on the context it is used
func (o *CdrConsentIntrospectOKBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with models.IntrospectResponse
	if err := o.IntrospectResponse.ContextValidate(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := o.contextValidateCdrArrangement(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := o.contextValidateCdrRegisterClientMetadata(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *CdrConsentIntrospectOKBody) contextValidateCdrArrangement(ctx context.Context, formats strfmt.Registry) error {

	if o.CdrArrangement != nil {
		if err := o.CdrArrangement.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("cdrConsentIntrospectOK" + "." + "cdr_arrangement")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("cdrConsentIntrospectOK" + "." + "cdr_arrangement")
			}
			return err
		}
	}

	return nil
}

func (o *CdrConsentIntrospectOKBody) contextValidateCdrRegisterClientMetadata(ctx context.Context, formats strfmt.Registry) error {

	if o.CdrRegisterClientMetadata != nil {
		if err := o.CdrRegisterClientMetadata.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("cdrConsentIntrospectOK" + "." + "cdr_register_client_metadata")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("cdrConsentIntrospectOK" + "." + "cdr_register_client_metadata")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *CdrConsentIntrospectOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *CdrConsentIntrospectOKBody) UnmarshalBinary(b []byte) error {
	var res CdrConsentIntrospectOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
