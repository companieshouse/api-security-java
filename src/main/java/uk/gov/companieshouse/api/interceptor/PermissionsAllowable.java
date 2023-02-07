package uk.gov.companieshouse.api.interceptor;

import java.util.Set;
import java.util.function.Function;

public interface PermissionsAllowable extends Function<String, Set<String>> {
}
