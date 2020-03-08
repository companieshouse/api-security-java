package uk.gov.companieshouse.api.util.security;

@FunctionalInterface
public interface TokenPermissions {

    /**
     * Check if the current key/value permission pair exists
     * 
     * @param key   The permission key
     * @param value The permission value
     * @return True if the key/value permission pair is present in the list of
     *         authorised token permission
     */
    boolean hasPermission(Permission.Key key, String value);
}
