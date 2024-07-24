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
	mvn org.sonarsource.scanner.maven:sonar-maven-plugin:3.4.0.905:sonar

.PHONY: sonar-pr-analysis
sonar-pr-analysis:
	mvn org.sonarsource.scanner.maven:sonar-maven-plugin:3.4.0.905:sonar -P sonar-pr-analysis
