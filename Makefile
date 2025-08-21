.PHONY: all
all: build

.PHONY: clean
clean:
	mvn clean

.PHONY: build
build:
	mvn compile

.PHONY: test
test: test-unit

.PHONY: test-unit
test-unit:
	mvn test

.PHONY: package
package:
ifndef version
	$(error No version given. Aborting)
endif
	$(info Packaging version: $(version))
	mvn versions:set -DnewVersion=$(version) -DgenerateBackupPoms=false
	mvn package -DskipTests=true

.PHONY: dist
dist: clean package

.PHONY: publish
publish:
	mvn jar:jar deploy:deploy

.PHONY: sonar
sonar:
	mvn sonar:sonar

.PHONY: sonar-pr-analysis
sonar-pr-analysis:
	mvn sonar:sonar -P sonar-pr-analysis

.PHONY: dependency-check
dependency-check:
	@ if [ -n "$(DEPENDENCY_CHECK_SUPPRESSIONS_HOME)" ]; then \
		if [ -d "$(DEPENDENCY_CHECK_SUPPRESSIONS_HOME)" ]; then \
			suppressions_home="$${DEPENDENCY_CHECK_SUPPRESSIONS_HOME}"; \
		else \
			printf -- 'DEPENDENCY_CHECK_SUPPRESSIONS_HOME is set, but its value "%s" does not point to a directory\n' "$(DEPENDENCY_CHECK_SUPPRESSIONS_HOME)"; \
			exit 1; \
		fi; \
	fi; \
	if [ ! -d "$${suppressions_home}" ]; then \
		suppressions_home_target_dir="./target/dependency-check-suppressions"; \
		if [ -d "$${suppressions_home_target_dir}" ]; then \
			suppressions_home="$${suppressions_home_target_dir}"; \
		else \
			mkdir -p "./target"; \
			git clone git@github.com:companieshouse/dependency-check-suppressions.git "$${suppressions_home_target_dir}" && \
				suppressions_home="$${suppressions_home_target_dir}"; \
		fi; \
	fi; \
	printf -- 'suppressions_home="%s"\n' "$${suppressions_home}"; \
	DEPENDENCY_CHECK_SUPPRESSIONS_HOME="$${suppressions_home}" "$${suppressions_home}/scripts/dependency-check-runner" --repo-name=chips-word-api

.PHONY: security-check
security-check: dependency-check
