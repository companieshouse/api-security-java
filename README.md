# api-security-java
Library for handling security in java API services.
Contains a generic set of authorisation utilities in Java including Interceptors that are deployed for use in multiple applications. Every filing/submission based application going forward should have its data wrapped in a Transaction and make use of the interceptor code from this library.

Things To consider
--

+ All development is now based on the `main` branch (Java 21).
+ Java 8 is no longer supported or maintained.

### Branching

+ Please create branch only from `main`
+ Please merge your changes only to [main](https://github.com/companieshouse/api-security-java) branch
+ All releases are generated from the `main` pipeline

### Versioning
+ Java 21 Major tags are generated from the pipeline
+ Version format example: `2.x.x`

### Pipeline

Please use this  `api-security-java` Concourse [Pipeline](https://ci-platform.companieshouse.gov.uk/teams/team-development/pipelines/api-security-java)

The `source-code-main` resource is triggered when:
+ A PR is created
+ A PR is merged into `main`

Once pipeline tasks complete successfully, use the generated tags for downstream references.