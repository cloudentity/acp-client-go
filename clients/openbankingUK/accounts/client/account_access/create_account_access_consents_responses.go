// Code generated by go-swagger; DO NOT EDIT.

package account_access

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/cloudentity/acp-client-go/clients/openbankingUK/accounts/models"
)

// CreateAccountAccessConsentsReader is a Reader for the CreateAccountAccessConsents structure.
type CreateAccountAccessConsentsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateAccountAccessConsentsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateAccountAccessConsentsCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateAccountAccessConsentsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateAccountAccessConsentsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateAccountAccessConsentsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewCreateAccountAccessConsentsMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewCreateAccountAccessConsentsNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewCreateAccountAccessConsentsUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateAccountAccessConsentsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCreateAccountAccessConsentsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewCreateAccountAccessConsentsCreated creates a CreateAccountAccessConsentsCreated with default headers values
func NewCreateAccountAccessConsentsCreated() *CreateAccountAccessConsentsCreated {
	return &CreateAccountAccessConsentsCreated{}
}

/*
CreateAccountAccessConsentsCreated describes a response with status code 201, with default header values.

Account Access Consents Created
*/
type CreateAccountAccessConsentsCreated struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	Payload *models.OBReadConsentResponse1
}

// IsSuccess returns true when this create account access consents created response has a 2xx status code
func (o *CreateAccountAccessConsentsCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create account access consents created response has a 3xx status code
func (o *CreateAccountAccessConsentsCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create account access consents created response has a 4xx status code
func (o *CreateAccountAccessConsentsCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create account access consents created response has a 5xx status code
func (o *CreateAccountAccessConsentsCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create account access consents created response a status code equal to that given
func (o *CreateAccountAccessConsentsCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create account access consents created response
func (o *CreateAccountAccessConsentsCreated) Code() int {
	return 201
}

func (o *CreateAccountAccessConsentsCreated) Error() string {
	return fmt.Sprintf("[POST /account-access-consents][%d] createAccountAccessConsentsCreated  %+v", 201, o.Payload)
}

func (o *CreateAccountAccessConsentsCreated) String() string {
	return fmt.Sprintf("[POST /account-access-consents][%d] createAccountAccessConsentsCreated  %+v", 201, o.Payload)
}

func (o *CreateAccountAccessConsentsCreated) GetPayload() *models.OBReadConsentResponse1 {
	return o.Payload
}

func (o *CreateAccountAccessConsentsCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	o.Payload = new(models.OBReadConsentResponse1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAccountAccessConsentsBadRequest creates a CreateAccountAccessConsentsBadRequest with default headers values
func NewCreateAccountAccessConsentsBadRequest() *CreateAccountAccessConsentsBadRequest {
	return &CreateAccountAccessConsentsBadRequest{}
}

/*
CreateAccountAccessConsentsBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type CreateAccountAccessConsentsBadRequest struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	Payload *models.OBErrorResponse1
}

// IsSuccess returns true when this create account access consents bad request response has a 2xx status code
func (o *CreateAccountAccessConsentsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create account access consents bad request response has a 3xx status code
func (o *CreateAccountAccessConsentsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create account access consents bad request response has a 4xx status code
func (o *CreateAccountAccessConsentsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create account access consents bad request response has a 5xx status code
func (o *CreateAccountAccessConsentsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create account access consents bad request response a status code equal to that given
func (o *CreateAccountAccessConsentsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create account access consents bad request response
func (o *CreateAccountAccessConsentsBadRequest) Code() int {
	return 400
}

func (o *CreateAccountAccessConsentsBadRequest) Error() string {
	return fmt.Sprintf("[POST /account-access-consents][%d] createAccountAccessConsentsBadRequest  %+v", 400, o.Payload)
}

func (o *CreateAccountAccessConsentsBadRequest) String() string {
	return fmt.Sprintf("[POST /account-access-consents][%d] createAccountAccessConsentsBadRequest  %+v", 400, o.Payload)
}

func (o *CreateAccountAccessConsentsBadRequest) GetPayload() *models.OBErrorResponse1 {
	return o.Payload
}

func (o *CreateAccountAccessConsentsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	o.Payload = new(models.OBErrorResponse1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAccountAccessConsentsUnauthorized creates a CreateAccountAccessConsentsUnauthorized with default headers values
func NewCreateAccountAccessConsentsUnauthorized() *CreateAccountAccessConsentsUnauthorized {
	return &CreateAccountAccessConsentsUnauthorized{}
}

/*
CreateAccountAccessConsentsUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CreateAccountAccessConsentsUnauthorized struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this create account access consents unauthorized response has a 2xx status code
func (o *CreateAccountAccessConsentsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create account access consents unauthorized response has a 3xx status code
func (o *CreateAccountAccessConsentsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create account access consents unauthorized response has a 4xx status code
func (o *CreateAccountAccessConsentsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create account access consents unauthorized response has a 5xx status code
func (o *CreateAccountAccessConsentsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create account access consents unauthorized response a status code equal to that given
func (o *CreateAccountAccessConsentsUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the create account access consents unauthorized response
func (o *CreateAccountAccessConsentsUnauthorized) Code() int {
	return 401
}

func (o *CreateAccountAccessConsentsUnauthorized) Error() string {
	return fmt.Sprintf("[POST /account-access-consents][%d] createAccountAccessConsentsUnauthorized ", 401)
}

func (o *CreateAccountAccessConsentsUnauthorized) String() string {
	return fmt.Sprintf("[POST /account-access-consents][%d] createAccountAccessConsentsUnauthorized ", 401)
}

func (o *CreateAccountAccessConsentsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewCreateAccountAccessConsentsForbidden creates a CreateAccountAccessConsentsForbidden with default headers values
func NewCreateAccountAccessConsentsForbidden() *CreateAccountAccessConsentsForbidden {
	return &CreateAccountAccessConsentsForbidden{}
}

/*
CreateAccountAccessConsentsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateAccountAccessConsentsForbidden struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	Payload *models.OBErrorResponse1
}

// IsSuccess returns true when this create account access consents forbidden response has a 2xx status code
func (o *CreateAccountAccessConsentsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create account access consents forbidden response has a 3xx status code
func (o *CreateAccountAccessConsentsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create account access consents forbidden response has a 4xx status code
func (o *CreateAccountAccessConsentsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create account access consents forbidden response has a 5xx status code
func (o *CreateAccountAccessConsentsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create account access consents forbidden response a status code equal to that given
func (o *CreateAccountAccessConsentsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create account access consents forbidden response
func (o *CreateAccountAccessConsentsForbidden) Code() int {
	return 403
}

func (o *CreateAccountAccessConsentsForbidden) Error() string {
	return fmt.Sprintf("[POST /account-access-consents][%d] createAccountAccessConsentsForbidden  %+v", 403, o.Payload)
}

func (o *CreateAccountAccessConsentsForbidden) String() string {
	return fmt.Sprintf("[POST /account-access-consents][%d] createAccountAccessConsentsForbidden  %+v", 403, o.Payload)
}

func (o *CreateAccountAccessConsentsForbidden) GetPayload() *models.OBErrorResponse1 {
	return o.Payload
}

func (o *CreateAccountAccessConsentsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	o.Payload = new(models.OBErrorResponse1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAccountAccessConsentsMethodNotAllowed creates a CreateAccountAccessConsentsMethodNotAllowed with default headers values
func NewCreateAccountAccessConsentsMethodNotAllowed() *CreateAccountAccessConsentsMethodNotAllowed {
	return &CreateAccountAccessConsentsMethodNotAllowed{}
}

/*
CreateAccountAccessConsentsMethodNotAllowed describes a response with status code 405, with default header values.

Method Not Allowed
*/
type CreateAccountAccessConsentsMethodNotAllowed struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this create account access consents method not allowed response has a 2xx status code
func (o *CreateAccountAccessConsentsMethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create account access consents method not allowed response has a 3xx status code
func (o *CreateAccountAccessConsentsMethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create account access consents method not allowed response has a 4xx status code
func (o *CreateAccountAccessConsentsMethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this create account access consents method not allowed response has a 5xx status code
func (o *CreateAccountAccessConsentsMethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this create account access consents method not allowed response a status code equal to that given
func (o *CreateAccountAccessConsentsMethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

// Code gets the status code for the create account access consents method not allowed response
func (o *CreateAccountAccessConsentsMethodNotAllowed) Code() int {
	return 405
}

func (o *CreateAccountAccessConsentsMethodNotAllowed) Error() string {
	return fmt.Sprintf("[POST /account-access-consents][%d] createAccountAccessConsentsMethodNotAllowed ", 405)
}

func (o *CreateAccountAccessConsentsMethodNotAllowed) String() string {
	return fmt.Sprintf("[POST /account-access-consents][%d] createAccountAccessConsentsMethodNotAllowed ", 405)
}

func (o *CreateAccountAccessConsentsMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewCreateAccountAccessConsentsNotAcceptable creates a CreateAccountAccessConsentsNotAcceptable with default headers values
func NewCreateAccountAccessConsentsNotAcceptable() *CreateAccountAccessConsentsNotAcceptable {
	return &CreateAccountAccessConsentsNotAcceptable{}
}

/*
CreateAccountAccessConsentsNotAcceptable describes a response with status code 406, with default header values.

Not Acceptable
*/
type CreateAccountAccessConsentsNotAcceptable struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this create account access consents not acceptable response has a 2xx status code
func (o *CreateAccountAccessConsentsNotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create account access consents not acceptable response has a 3xx status code
func (o *CreateAccountAccessConsentsNotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create account access consents not acceptable response has a 4xx status code
func (o *CreateAccountAccessConsentsNotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this create account access consents not acceptable response has a 5xx status code
func (o *CreateAccountAccessConsentsNotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this create account access consents not acceptable response a status code equal to that given
func (o *CreateAccountAccessConsentsNotAcceptable) IsCode(code int) bool {
	return code == 406
}

// Code gets the status code for the create account access consents not acceptable response
func (o *CreateAccountAccessConsentsNotAcceptable) Code() int {
	return 406
}

func (o *CreateAccountAccessConsentsNotAcceptable) Error() string {
	return fmt.Sprintf("[POST /account-access-consents][%d] createAccountAccessConsentsNotAcceptable ", 406)
}

func (o *CreateAccountAccessConsentsNotAcceptable) String() string {
	return fmt.Sprintf("[POST /account-access-consents][%d] createAccountAccessConsentsNotAcceptable ", 406)
}

func (o *CreateAccountAccessConsentsNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewCreateAccountAccessConsentsUnsupportedMediaType creates a CreateAccountAccessConsentsUnsupportedMediaType with default headers values
func NewCreateAccountAccessConsentsUnsupportedMediaType() *CreateAccountAccessConsentsUnsupportedMediaType {
	return &CreateAccountAccessConsentsUnsupportedMediaType{}
}

/*
CreateAccountAccessConsentsUnsupportedMediaType describes a response with status code 415, with default header values.

Unsupported Media Type
*/
type CreateAccountAccessConsentsUnsupportedMediaType struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this create account access consents unsupported media type response has a 2xx status code
func (o *CreateAccountAccessConsentsUnsupportedMediaType) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create account access consents unsupported media type response has a 3xx status code
func (o *CreateAccountAccessConsentsUnsupportedMediaType) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create account access consents unsupported media type response has a 4xx status code
func (o *CreateAccountAccessConsentsUnsupportedMediaType) IsClientError() bool {
	return true
}

// IsServerError returns true when this create account access consents unsupported media type response has a 5xx status code
func (o *CreateAccountAccessConsentsUnsupportedMediaType) IsServerError() bool {
	return false
}

// IsCode returns true when this create account access consents unsupported media type response a status code equal to that given
func (o *CreateAccountAccessConsentsUnsupportedMediaType) IsCode(code int) bool {
	return code == 415
}

// Code gets the status code for the create account access consents unsupported media type response
func (o *CreateAccountAccessConsentsUnsupportedMediaType) Code() int {
	return 415
}

func (o *CreateAccountAccessConsentsUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[POST /account-access-consents][%d] createAccountAccessConsentsUnsupportedMediaType ", 415)
}

func (o *CreateAccountAccessConsentsUnsupportedMediaType) String() string {
	return fmt.Sprintf("[POST /account-access-consents][%d] createAccountAccessConsentsUnsupportedMediaType ", 415)
}

func (o *CreateAccountAccessConsentsUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewCreateAccountAccessConsentsTooManyRequests creates a CreateAccountAccessConsentsTooManyRequests with default headers values
func NewCreateAccountAccessConsentsTooManyRequests() *CreateAccountAccessConsentsTooManyRequests {
	return &CreateAccountAccessConsentsTooManyRequests{}
}

/*
CreateAccountAccessConsentsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type CreateAccountAccessConsentsTooManyRequests struct {

	/* Number in seconds to wait
	 */
	RetryAfter int64

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this create account access consents too many requests response has a 2xx status code
func (o *CreateAccountAccessConsentsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create account access consents too many requests response has a 3xx status code
func (o *CreateAccountAccessConsentsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create account access consents too many requests response has a 4xx status code
func (o *CreateAccountAccessConsentsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create account access consents too many requests response has a 5xx status code
func (o *CreateAccountAccessConsentsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create account access consents too many requests response a status code equal to that given
func (o *CreateAccountAccessConsentsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create account access consents too many requests response
func (o *CreateAccountAccessConsentsTooManyRequests) Code() int {
	return 429
}

func (o *CreateAccountAccessConsentsTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /account-access-consents][%d] createAccountAccessConsentsTooManyRequests ", 429)
}

func (o *CreateAccountAccessConsentsTooManyRequests) String() string {
	return fmt.Sprintf("[POST /account-access-consents][%d] createAccountAccessConsentsTooManyRequests ", 429)
}

func (o *CreateAccountAccessConsentsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header Retry-After
	hdrRetryAfter := response.GetHeader("Retry-After")

	if hdrRetryAfter != "" {
		valretryAfter, err := swag.ConvertInt64(hdrRetryAfter)
		if err != nil {
			return errors.InvalidType("Retry-After", "header", "int64", hdrRetryAfter)
		}
		o.RetryAfter = valretryAfter
	}

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewCreateAccountAccessConsentsInternalServerError creates a CreateAccountAccessConsentsInternalServerError with default headers values
func NewCreateAccountAccessConsentsInternalServerError() *CreateAccountAccessConsentsInternalServerError {
	return &CreateAccountAccessConsentsInternalServerError{}
}

/*
CreateAccountAccessConsentsInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type CreateAccountAccessConsentsInternalServerError struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	Payload *models.OBErrorResponse1
}

// IsSuccess returns true when this create account access consents internal server error response has a 2xx status code
func (o *CreateAccountAccessConsentsInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create account access consents internal server error response has a 3xx status code
func (o *CreateAccountAccessConsentsInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create account access consents internal server error response has a 4xx status code
func (o *CreateAccountAccessConsentsInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this create account access consents internal server error response has a 5xx status code
func (o *CreateAccountAccessConsentsInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this create account access consents internal server error response a status code equal to that given
func (o *CreateAccountAccessConsentsInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the create account access consents internal server error response
func (o *CreateAccountAccessConsentsInternalServerError) Code() int {
	return 500
}

func (o *CreateAccountAccessConsentsInternalServerError) Error() string {
	return fmt.Sprintf("[POST /account-access-consents][%d] createAccountAccessConsentsInternalServerError  %+v", 500, o.Payload)
}

func (o *CreateAccountAccessConsentsInternalServerError) String() string {
	return fmt.Sprintf("[POST /account-access-consents][%d] createAccountAccessConsentsInternalServerError  %+v", 500, o.Payload)
}

func (o *CreateAccountAccessConsentsInternalServerError) GetPayload() *models.OBErrorResponse1 {
	return o.Payload
}

func (o *CreateAccountAccessConsentsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	o.Payload = new(models.OBErrorResponse1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
