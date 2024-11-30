## Queue processor
`queue.py` is the script responsible for processing and validating the submissions sent via the [List API](https://github.com/freedomofpress/webcat/tree/main/list_server#list-api) (or its [graphical frontend](https://github.com/freedomofpress/webcat/blob/main/web/list.html)).

The validation process is currently dicussed in https://github.com/freedomofpress/webcat/issues/8.

The CSP requirements are currently dicussed in https://github.com/freedomofpress/webcat/issues/9.

As we are in a proof of concept state, this logix is highly experimental and feedback is welcome.

### Processing list changes
#### Type of changes
There are three possible user requested actions:
 - `ADD`
 - `MODIFY`
 - `DELETE`

And the following possible system actions:
 - `DOMAIN_DELETED`: the included domain is no longer registered, and it should be marked for removal.
 - `SERVICE_MODIFIED`: community-supported emergency change, such as a high profile compromise has happened and it is reasonable not to wait `WAITING_DELAY` for changes.

They have different configuration requirements in order to be succesful, but they follow a very similar validation logic, with mostly the same steps involved.

#### Submission statuses
 - *Final* does not allow for retries: the requested change is discarded and the admin contact is notified.
 - **Needs Investigation* does not allow retries. However, the failure happened in an unexpected situation (such as, the transparency log personality detected inconsistencies). This should never happen, but if it does, the incident must be investigated,


| **Current Phase**       | **Status Code**                   | **Final** | **Needs Investigation** | **Description**                                                                                 | **Next Successful State**         | **Next Error State**                 |
|--------------------------|-----------------------------------|-----------|--------------------------|-------------------------------------------------------------------------------------------------|------------------------------------|---------------------------------------|
| Submission              | SUBMITTED                        | No        | No                       | Request received and saved.                                                                     | PRELIMINARY_VALIDATION_IN_PROGRESS | -                                     |
| Preliminary Validation  | PRELIMINARY_VALIDATION_IN_PROGRESS | No        | No                       | Initial checks in progress.                                                                     | PRELIMINARY_VALIDATION_OK          | PRELIMINARY_VALIDATION_ERROR          |
| Preliminary Validation  | PRELIMINARY_VALIDATION_OK        | No        | No                       | Initial validation successful.                                                                  | SUBMISSION_TO_LOG_IN_PROGRESS      | -                                     |
| Preliminary Validation  | PRELIMINARY_VALIDATION_ERROR     | Yes       | No                       | Configuration error during initial validation; change discarded.                                | -                                  | -                                     |
| Submission to Log       | SUBMISSION_TO_LOG_IN_PROGRESS    | No        | No                       | Sending to Transparency API.                                                                    | SUBMISSION_TO_LOG_OK               | SUBMISSION_TO_LOG_ERROR               |
| Submission to Log       | SUBMISSION_TO_LOG_OK             | No        | No                       | Submission accepted by Transparency API.                                                       | LOG_INCLUSION_OK                   | -                                     |
| Submission to Log       | SUBMISSION_TO_LOG_ERROR          | Yes       | Yes                      | Transparency API rejected submission; change discarded.                                         | -                                  | -                                     |
| Log Inclusion           | LOG_INCLUSION_OK                | No        | No                       | Transparency API returned a valid log inclusion proof; merge successful.                       | WAITING_DELAY                      | -                                     |
| Log Inclusion           | LOG_INCLUSION_ERROR             | Yes       | Yes                      | Log inclusion proof failed; change discarded.                                                  | -                                  | -                                     |
| Waiting Period          | WAITING_DELAY                   | No        | No                       | All steps successful; waiting period before secondary validation.                              | SECOND_VALIDATION_IN_PROGRESS      | -                                     |
| Secondary Validation    | SECOND_VALIDATION_IN_PROGRESS   | No        | No                       | Secondary checks in progress.                                                                   | SECOND_VALIDATION_OK               | SECOND_VALIDATION_ERROR               |
| Secondary Validation    | SECOND_VALIDATION_OK            | No        | No                       | Secondary validation successful; configuration matches the first validation.                   | SECOND_SUBMISSION_TO_LOG_IN_PROGRESS | -                                     |
| Secondary Validation    | SECOND_VALIDATION_ERROR         | Yes       | No                       | Secondary validation failed; configuration mismatch or error; change discarded.                | -                                  | -                                     |
| Second Submission to Log| SECOND_SUBMISSION_TO_LOG_IN_PROGRESS | No        | No                       | Sending results of secondary validation to Transparency API.                                   | SECOND_SUBMISSION_TO_LOG_OK        | SECOND_SUBMISSION_TO_LOG_ERROR        |
| Second Submission to Log| SECOND_SUBMISSION_TO_LOG_OK      | No        | No                       | Second submission accepted by Transparency API.                                                | SECOND_LOG_INCLUSION_OK            | -                                     |
| Second Submission to Log| SECOND_SUBMISSION_TO_LOG_ERROR   | Yes       | Yes                      | Transparency API rejected second submission; change discarded.                                 | -                                  | -                                     |
| Second Log Inclusion    | SECOND_LOG_INCLUSION_OK         | No        | No                       | Transparency API returned a valid log inclusion proof; merge successful.                       | COMPLETED                          | -                                     |
| Second Log Inclusion    | SECOND_LOG_INCLUSION_ERROR      | Yes       | Yes                      | Log inclusion proof failed during second inclusion; change discarded.                          | -                                  | -                                     |
| Completion              | COMPLETED                       | Yes       | No                       | Process completed successfully; change included in the next list distribution.                 | -                                  | -                                     |
