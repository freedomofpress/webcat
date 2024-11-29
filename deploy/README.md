## Config
The whole infrastructure expects to run under a single domain, that has to be provided as a variable to terraform and be delegated on Route53 to the same account.

### Add the domain
As adding the domain can't be done automatically, because it requires first adding it to Route53, and then getting the delegated nameservers to add to the top level zone via the registrar, the setup is splitted in two phases.

 1. `cd domain`
 2. `terraform init`
 3. `terraform apply -var="main_domain=<mydomain.com>"`
 4. Terraform should output the delegated nameservers assigned by Route53.
 5. Go to the domain registrar management panel and change the nameservers, wait a bit for propagation.

### Deploy everything else
The domain must be the same from the previous step.

 1. `cd infra`
 2. `terraform init`
 3. `terraform apply -var="main_domain=<mydomain.com>"`

Most terraform output here is just debug, and it is not specifically necessary for any further task. Just check that terrafoirm completes successfully.

## Proposed architecture
| Scope        | Hostname       | Type        | Public | Connects to                                   | Description                                                                                                                                                                        |
| ------------ | -------------- | ----------- | ------ | --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Transparency | log-db         | RDS         | No     |                                               | RDS instance to use as a MYSQL hosted backend for the Trillian database and the personality database.                                                                              |
| Transparency | log-trillian   | EC2         | No     | log-db                                        | EC2 instance running Trillian as a system service. Needs a MYSQL connection string and a LOG_TREE_ID, passable at runtime.                                                         |
| Transparency | log-api    | Lambda      | No     | log-db, log-trillian                          | Lambda that runs the Flask API that constitutes the Trillian personality. Need to access log-trillian via gRPC and log-db via MYSQL since it has its own database for consistency. |
| Transparency | log-api        | API Gateway | Yes    |                                       | API Gateway that provides the public access to log-personality.transparency.cat.                                                                                                   |
| Transparency | log            | S3          | Yes    |                                               | S3 that hosts a static website to provide a basic user interface to log-api.                                                                                                       |
| List         | list-db        | RDS         | No     |                                               | Separate RDS (MYSQL or PGSQL) instance that keeps track of submissions and changes to the list, before or during validation.                                                       |
| List         | list-api   | Lambda      | No     | list-db                                       | Lambda that handles the public API to ask for list changes: Addition, Modification, Deletion. Connects to RDS on list-db.                                                          |
| List         | list-api       | API Gateway | Yes    |                                   | API Gateway that provides the public access to log-personality.transparency.cat.                                                                                                   |
| List         | list           | S3          | Yes    |                                               | S3 that hosts a static website to provide a basic user interface to list-api.                                                                                                      |
| List         | list-queue | EventBridge | No     | list-db                                       | EventBridge job (every 15 mins?) that checks submissions and update requests for the list.                                                                                         |
| List         | list-builder   | EventBridge | No     | list-db, log-db, kms-log, kms-list, list-dist | EventBridge job (daily?) that checks, builds, signs and publish a new list if necessary.                                                                                           |
| List         | kms-log        | Managed Key | No     |                                               | Key used to sign entries sent to log-api.                                                                                                                                          |
| List         | kms-list       | Managed Key | No     |                                               | Key used to sign the published list and its updates.                                                                                                                               |
| List         | list-dist      | S3          | Yes    |                                               | S3 used to distrbute the list and its updates.                                                                                                                                     |
