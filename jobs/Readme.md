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
 - `SUBMITTED`: the List API has received the request and saved its details (the type of change, and the submitted hostname).
 - `PRELIMINARY_VALIDATION_IN_PROGRESS`: the queue script is currently running the first set of checks.
 - `PRELIMINARY_VALIDATION_ERROR`: the queue script has encountered a configuration error while performing the initial validation. _This is a final status and the requested change is discarded._
 - `PRELIMINARY_VALIDATION_OK`: the queue script has succesfully completed the preliminary validation. Soon the script will initiate the next steps.
 - `SUBMISSION_TO_LOG_IN_PROGRESS`: after `PRELIMINARY_VALIDATION_OK` the queue script has validated the requested change and is sending it to the [Transparency API](https://github.com/freedomofpress/webcat/blob/main/transparency_server/api.py) for inclusion.
 - `SUBMISSION_TO_LOG_ERROR`: the Transparecy API has rejected the submission, an error has occurred. _This is a final status and the requested change is discarded. The reason must be investigated._
 - `SUBMISSION_TO_LOG_OK`: the Transparency API has accepted the inclusion of the proposed change.
 - `LOG_INCLUSION_OK`: the Transparency API has returned a valid log inclusion proof, meaning that the merge of the leaf was completed succesfully.
 - `LOG_INCLUSION_ERROR`: the transparency log has failed to produce an inclusion proof, and as a consequence, probably to merge the leaf. . _This is a final status and the requested change is discarded. The reason must be investigated._
 - `WAITING_DELAY`: all previous steps completed succesfully. The queue script is now waiting the configured time (7 days?) before proceeding further, in order to allow web administrators to react to unwanted change (hacked servers?).
 - `SECOND_VALIDATION_IN_PROGRESS`: `WAITING_DELAY` time has passed. The queue script will perform again the same checks of `PRELIMINARY_VALIDATION_IN_PROGRESS` and check for the same results.
 - `SECOND_VALIDATION_ERROR`: the queue script has encountered a configuration error while performing the secondary validation, or the configuration does not match the one found during `PRELIMINARY_VALIDATION_IN_PROGRESS`. _This is a final status and the requested change is discarded._
 - `SECOND_VALIDATION_OK`: the queue script has succesfully completed the second validation, and the configuration matches the one found during `PRELIMINARY_VALIDATION_IN_PROGRESS`.
 - `SECOND_SUBMISSION_TO_LOG_IN_PROGRESS`: sending the result of the second validation to the Transparency API.
 - `SECOND_SUBMISSION_TO_LOG_ERROR`: the Transparency API has rejected the second validation. _This is a final status and the requested change is discarded. The reason must be investigated._
 - `SECOND_SUBMISSION_TO_LOG_OK`: the Transparency API has accepted the inclusion of the payload with the information about the second validation status.
 - `SECOND_LOG_INCLUSION_OK`: the Transparency API has returned a valid log inclusion proof, meaning that the merge of the leaf was completed succesfully.
 - `SECOND_LOG_INCLUSION_ERROR`: the transparency log has failed to produce an inclusion proof, and as a consequence, probably to merge the leaf.  _This is a final status and the requested change is discarded. The reason must be investigated._
 - `COMPLETED`: the process has completed and the script will update the internal list. The change will be included in the next list distribution. _This is a final status and the requested change is accepted._
