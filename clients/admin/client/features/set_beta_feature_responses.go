// Code generated by go-swagger; DO NOT EDIT.

package features

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// SetBetaFeatureReader is a Reader for the SetBetaFeature structure.
type SetBetaFeatureReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SetBetaFeatureReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewSetBetaFeatureNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewSetBetaFeatureBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewSetBetaFeatureUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSetBetaFeatureForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSetBetaFeatureNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewSetBetaFeatureUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSetBetaFeatureTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /beta-feature] setBetaFeature", response, response.Code())
	}
}

// NewSetBetaFeatureNoContent creates a SetBetaFeatureNoContent with default headers values
func NewSetBetaFeatureNoContent() *SetBetaFeatureNoContent {
	return &SetBetaFeatureNoContent{}
}

/*
SetBetaFeatureNoContent describes a response with status code 204, with default header values.

	beta feature set
*/
type SetBetaFeatureNoContent struct {
}

// IsSuccess returns true when this set beta feature no content response has a 2xx status code
func (o *SetBetaFeatureNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this set beta feature no content response has a 3xx status code
func (o *SetBetaFeatureNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set beta feature no content response has a 4xx status code
func (o *SetBetaFeatureNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this set beta feature no content response has a 5xx status code
func (o *SetBetaFeatureNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this set beta feature no content response a status code equal to that given
func (o *SetBetaFeatureNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the set beta feature no content response
func (o *SetBetaFeatureNoContent) Code() int {
	return 204
}

func (o *SetBetaFeatureNoContent) Error() string {
	return fmt.Sprintf("[POST /beta-feature][%d] setBetaFeatureNoContent ", 204)
}

func (o *SetBetaFeatureNoContent) String() string {
	return fmt.Sprintf("[POST /beta-feature][%d] setBetaFeatureNoContent ", 204)
}

func (o *SetBetaFeatureNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewSetBetaFeatureBadRequest creates a SetBetaFeatureBadRequest with default headers values
func NewSetBetaFeatureBadRequest() *SetBetaFeatureBadRequest {
	return &SetBetaFeatureBadRequest{}
}

/*
SetBetaFeatureBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type SetBetaFeatureBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this set beta feature bad request response has a 2xx status code
func (o *SetBetaFeatureBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set beta feature bad request response has a 3xx status code
func (o *SetBetaFeatureBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set beta feature bad request response has a 4xx status code
func (o *SetBetaFeatureBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this set beta feature bad request response has a 5xx status code
func (o *SetBetaFeatureBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this set beta feature bad request response a status code equal to that given
func (o *SetBetaFeatureBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the set beta feature bad request response
func (o *SetBetaFeatureBadRequest) Code() int {
	return 400
}

func (o *SetBetaFeatureBadRequest) Error() string {
	return fmt.Sprintf("[POST /beta-feature][%d] setBetaFeatureBadRequest  %+v", 400, o.Payload)
}

func (o *SetBetaFeatureBadRequest) String() string {
	return fmt.Sprintf("[POST /beta-feature][%d] setBetaFeatureBadRequest  %+v", 400, o.Payload)
}

func (o *SetBetaFeatureBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetBetaFeatureBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetBetaFeatureUnauthorized creates a SetBetaFeatureUnauthorized with default headers values
func NewSetBetaFeatureUnauthorized() *SetBetaFeatureUnauthorized {
	return &SetBetaFeatureUnauthorized{}
}

/*
SetBetaFeatureUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type SetBetaFeatureUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this set beta feature unauthorized response has a 2xx status code
func (o *SetBetaFeatureUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set beta feature unauthorized response has a 3xx status code
func (o *SetBetaFeatureUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set beta feature unauthorized response has a 4xx status code
func (o *SetBetaFeatureUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this set beta feature unauthorized response has a 5xx status code
func (o *SetBetaFeatureUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this set beta feature unauthorized response a status code equal to that given
func (o *SetBetaFeatureUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the set beta feature unauthorized response
func (o *SetBetaFeatureUnauthorized) Code() int {
	return 401
}

func (o *SetBetaFeatureUnauthorized) Error() string {
	return fmt.Sprintf("[POST /beta-feature][%d] setBetaFeatureUnauthorized  %+v", 401, o.Payload)
}

func (o *SetBetaFeatureUnauthorized) String() string {
	return fmt.Sprintf("[POST /beta-feature][%d] setBetaFeatureUnauthorized  %+v", 401, o.Payload)
}

func (o *SetBetaFeatureUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetBetaFeatureUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetBetaFeatureForbidden creates a SetBetaFeatureForbidden with default headers values
func NewSetBetaFeatureForbidden() *SetBetaFeatureForbidden {
	return &SetBetaFeatureForbidden{}
}

/*
SetBetaFeatureForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type SetBetaFeatureForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this set beta feature forbidden response has a 2xx status code
func (o *SetBetaFeatureForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set beta feature forbidden response has a 3xx status code
func (o *SetBetaFeatureForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set beta feature forbidden response has a 4xx status code
func (o *SetBetaFeatureForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this set beta feature forbidden response has a 5xx status code
func (o *SetBetaFeatureForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this set beta feature forbidden response a status code equal to that given
func (o *SetBetaFeatureForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the set beta feature forbidden response
func (o *SetBetaFeatureForbidden) Code() int {
	return 403
}

func (o *SetBetaFeatureForbidden) Error() string {
	return fmt.Sprintf("[POST /beta-feature][%d] setBetaFeatureForbidden  %+v", 403, o.Payload)
}

func (o *SetBetaFeatureForbidden) String() string {
	return fmt.Sprintf("[POST /beta-feature][%d] setBetaFeatureForbidden  %+v", 403, o.Payload)
}

func (o *SetBetaFeatureForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetBetaFeatureForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetBetaFeatureNotFound creates a SetBetaFeatureNotFound with default headers values
func NewSetBetaFeatureNotFound() *SetBetaFeatureNotFound {
	return &SetBetaFeatureNotFound{}
}

/*
SetBetaFeatureNotFound describes a response with status code 404, with default header values.

Not found
*/
type SetBetaFeatureNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this set beta feature not found response has a 2xx status code
func (o *SetBetaFeatureNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set beta feature not found response has a 3xx status code
func (o *SetBetaFeatureNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set beta feature not found response has a 4xx status code
func (o *SetBetaFeatureNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this set beta feature not found response has a 5xx status code
func (o *SetBetaFeatureNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this set beta feature not found response a status code equal to that given
func (o *SetBetaFeatureNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the set beta feature not found response
func (o *SetBetaFeatureNotFound) Code() int {
	return 404
}

func (o *SetBetaFeatureNotFound) Error() string {
	return fmt.Sprintf("[POST /beta-feature][%d] setBetaFeatureNotFound  %+v", 404, o.Payload)
}

func (o *SetBetaFeatureNotFound) String() string {
	return fmt.Sprintf("[POST /beta-feature][%d] setBetaFeatureNotFound  %+v", 404, o.Payload)
}

func (o *SetBetaFeatureNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetBetaFeatureNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetBetaFeatureUnprocessableEntity creates a SetBetaFeatureUnprocessableEntity with default headers values
func NewSetBetaFeatureUnprocessableEntity() *SetBetaFeatureUnprocessableEntity {
	return &SetBetaFeatureUnprocessableEntity{}
}

/*
SetBetaFeatureUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type SetBetaFeatureUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this set beta feature unprocessable entity response has a 2xx status code
func (o *SetBetaFeatureUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set beta feature unprocessable entity response has a 3xx status code
func (o *SetBetaFeatureUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set beta feature unprocessable entity response has a 4xx status code
func (o *SetBetaFeatureUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this set beta feature unprocessable entity response has a 5xx status code
func (o *SetBetaFeatureUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this set beta feature unprocessable entity response a status code equal to that given
func (o *SetBetaFeatureUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the set beta feature unprocessable entity response
func (o *SetBetaFeatureUnprocessableEntity) Code() int {
	return 422
}

func (o *SetBetaFeatureUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /beta-feature][%d] setBetaFeatureUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *SetBetaFeatureUnprocessableEntity) String() string {
	return fmt.Sprintf("[POST /beta-feature][%d] setBetaFeatureUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *SetBetaFeatureUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetBetaFeatureUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetBetaFeatureTooManyRequests creates a SetBetaFeatureTooManyRequests with default headers values
func NewSetBetaFeatureTooManyRequests() *SetBetaFeatureTooManyRequests {
	return &SetBetaFeatureTooManyRequests{}
}

/*
SetBetaFeatureTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type SetBetaFeatureTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this set beta feature too many requests response has a 2xx status code
func (o *SetBetaFeatureTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set beta feature too many requests response has a 3xx status code
func (o *SetBetaFeatureTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set beta feature too many requests response has a 4xx status code
func (o *SetBetaFeatureTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this set beta feature too many requests response has a 5xx status code
func (o *SetBetaFeatureTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this set beta feature too many requests response a status code equal to that given
func (o *SetBetaFeatureTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the set beta feature too many requests response
func (o *SetBetaFeatureTooManyRequests) Code() int {
	return 429
}

func (o *SetBetaFeatureTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /beta-feature][%d] setBetaFeatureTooManyRequests  %+v", 429, o.Payload)
}

func (o *SetBetaFeatureTooManyRequests) String() string {
	return fmt.Sprintf("[POST /beta-feature][%d] setBetaFeatureTooManyRequests  %+v", 429, o.Payload)
}

func (o *SetBetaFeatureTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetBetaFeatureTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}