## Claimant Models
As the official [Trillian documentation suggests](https://github.com/google/trillian/tree/master/docs/claimantmodel), reasoning in terms of a Claimant Model is helpful when building transparency logs applications.
[Another helpful resource is the firmware transparency example documentation](https://github.com/google/trillian-examples/tree/master/binary_transparency/firmware/docs/design).

### Assumptions/Requirements
All submissions are public: websites who want to enroll in this service cannot do so privately. Even when a submission may end up resulting invalid, the submission itself is still discoverable. While we might think of a model with some level of privacy specifically for enrolling Hidden Services, at the moment this is not implemented.

### Model

#### System<sup>SUBMISSION_SERVER</sup>:

 - Claim<sup>SUBMISSION_SERVER</sup> - I, Submission Server, claim that that someone has requested a list operation with the following manifest and that I have live verified the domain for compliance with basic inclusion criteria (including existing list status) and matching the manifest:
    1. _domain_: example.com
    2. _action_: add/modify/delete
    3. _policy_: (only if _action_==add/modify) (_identity_ and _issuer_) and (_identity_ and _issuer_)

 - Statement<sup>SUBMISSION_SERVER</sup> - Signesd list operation.
 - Claimant<sup>SUBMISSION_SERVER</sup> - Submission Server operator.
 - Believer<sup>SUBMISSION_SERVER</sup>
   1. Compiled list builder.
   2. Browsers.

- Verifier<sup>SUBMISSION_SERVER</sup>
  1. Website owners (which are expected to be submitters).
  2. Compliance auditors: to monitor the list and the websites for compliance.
  3. Log auditors: to monitor cryptographic consistence and append-only nature of the list.
  4. Compiled list auditors: to have fully reporducible list builds.

 - Arbiter<sup>SUBMISSION_SERVER</sup>
  1. Browsers/plugin maintainers
  2. Security community

#### System<sup>LIST_TRANSPRENCY_LOG</sup>:

 - Claim<sup>LIST_TRANSPARENCY_LOG</sup> - - I, log operator, make available:
   1. A globally consistent, append-only log of Statement<sup>SUBMISSION_SERVER</sup>
   2. All associated metadata with such statements, including policies.

 - Statement<sup>LIST_TRANSPARENCY_LOG</sup> - log checkpoint ("_Signed tree head_")
 - Claimant<sup>LIST_TRANSPARENCY_LOG</sup> - List transparency log operator (e.g.: separate entity from the Submission Server)
 - Believer<sup>LIST_TRANSPARENCY_LOG</sup>
   1. Believer<sup>SUBMISSION_SERVER</sup>
   2. Verifier<sup>SUBMISSION_SERVER</sup>
 - Verifier<sup>LIST_TRANSPARENCY_LOG</sup>
   1. Other log operators (would be nice to have distributed logs with p2p consensus, wouldn't it?)
   2. 3rd parties with an interest in monitoring
 




   
