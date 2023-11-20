# api-security-java
Library for handling security in java API services.
Contains a generic set of authorisation utilities in Java including Interceptors that are deployed for use in multiple applications. Every filing/submission based application going forward should have its data wrapped in a Transaction and make use of the interceptor code from this library.

Things To consider
--

+ Always make sure any code changes you make get copied across to `main-8` (compatible with Java 8) also to `main` (compatible with Java 21)

###### Changes Specific to Java 8

+ Please raise a PR to merge your changes only to [main-8](https://github.com/companieshouse/api-security-java/tree/main-8) branch
+ Use Java 8 Major tags generated from pipeline in your references (example : tags 0.x.x for java 8)

###### Changes Specific to Java 21

+ Please merge your changes only to [main](https://github.com/companieshouse/api-security-java) branch
+ Use Java 21 Major tags generated from pipeline in your references (example : tags 2.x.x for java 21)

###### Pipeline

+ Please use this [Pipeline](https://ci-platform.companieshouse.gov.uk/teams/team-development/pipelines/api-security-java) and make sure respective `source-code-main` or `source-code-main-8` task gets started once the PR is created or after the PR is merged to `main` or `main-8` and once the pipeline tasks are complete then use the created tags respectively.