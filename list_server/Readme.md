# List API
The purpose of the List API is to allow web server administrators to enroll, modify, or unenroll for the Webcat preload list. Under normal circumstances, changes should be very unlikely: any application can be updated as long as the authors keeps a threhold of their Sigstore identities.

## Deployment
The Python Flask API uses Mysql as a backend, and the schema is provided and should be create manually. Currently, it is implemented to run as Lambda with an API Gateway in front as [defined buy the deployment script](https://github.com/freedomofpress/webcat/blob/main/deploy/infra/list-api.tf).

### Build the Lambda zip
The following command will create a zipfile with all the necessary dependencies for it to run serverless in `../dist/list-lambda.zip`. As with building any Lambda function, the python interpreter and the os architecture should be as close as possible to the Lambda provider ones.

```make build```

### Environment Variables

The following environment variables are required for the API to connect to the MySQL database:

- `DB_HOST`: Database hostname.
- `DB_PORT`: Database port.
- `DB_USER`: Database username.
- `DB_PASSWORD`: Database password.
- `DB_NAME`: Database name.

## API Definition
All submissions are public by design.

### Table of Contents

- [Environment Variables](#environment-variables)
- [Endpoints](#endpoints)
  - [`GET /`](#get-)
  - [`POST /submission`](#post-submission)
  - [`GET /submission`](#get-submission)
  - [`GET /submission/{id}`](#get-submissionid)
- [Error Handling](#error-handling)
- [Database Schema](#database-schema)

---



### Endpoints

#### `GET /`

**Description**: Health check endpoint.

**Response**:
`{"status": "OK"}`

#### `POST /submission`

**Description**: Adds a new submission with a specified action.

**Request Body**:
- `fqdn`: Fully qualified domain name for the submission.
- `action`: Action to perform (`ADD`, `MODIFY`, `DELETE`).

**Example Request**:
`{"fqdn": "example.com", "action": "ADD"}`

**Response**:
- **200 OK**: `{"status": "OK", "id": "<submission_id>"}`
- **400 Bad Request**: `{"status": "KO", "message": "Missing the `fqdn` or `action` keys."}`
- **500 Internal Server Error**: `{"status": "KO", "message": "A server error has occurred, contact an administrator."}`

#### `GET /submission`

**Description**: Returns the total count of submissions.

**Response**:
- **200 OK**: `{"status": "OK", "total_submissions": "<total>"}`

#### `GET /submission/{id}`

**Description**: Retrieves details for a specific submission by `id`.

**Path Parameter**:
- `id`: The unique identifier of the submission.

**Response**:
- **200 OK**: `{"status": "OK", "id": "<submission_id>", "fqdn": "<fqdn>", "type": "<action_type>", "status": "<current_status>", "log": [{"status_id": "<status_id>", "timestamp": "<timestamp>"}]}`
- **404 Not Found**: `{"status": "KO", "message": "Submission with the id provided not found."}`

### Error Handling

This API includes custom error handling for the following:

- **MethodNotAllowed (405)**: When an unsupported method is used.
- **UnsupportedMediaType (415)**: When the request media type is not supported.
- **HTTPException**: Catches HTTP exceptions and returns the appropriate error message and status code.
- **Generic Exception Handler (500)**: Catches any unexpected server errors.

Example error response:
`{"status": "KO", "message": "An unexpected error occurred"}`



---
