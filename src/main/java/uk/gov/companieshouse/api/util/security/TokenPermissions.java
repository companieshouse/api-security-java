package uk.gov.companieshouse.api.util.security;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;

/**
 * Reads and stores the authorised ERIC token permissions from a request and
 * provides a method to check them individually
 */
public class TokenPermissions {

    final String authorisedTokenPermissions;
    Map<String, List<String>> permissions;

    public TokenPermissions(HttpServletRequest request) {
        authorisedTokenPermissions = AuthorisationUtil.getAuthorisedTokenPermissions(request);
    }

    /**
     * Check if the current key/value permission pair exists
     * 
     * @param key   The permission key
     * @param value The permission value
     * @return True if the key/value permission pair is present in the list of
     *         authorised token permission
     */
    public boolean hasPermission(Permission.Key key, String value) {
        if (permissions == null) {
            permissions = readTokenPermissions(authorisedTokenPermissions);
        }

        return permissions.getOrDefault(key.toString(), Collections.emptyList()).contains(value);
    }

    /**
     * The ERIC token permission is of the format: 
     *       "key1=valueA key2=valueB key3=valueC,valueD,valueE"
     * i.e. space separated key value pairs which themselves are separated by "=".
     * values can also be split on a comma so we end up with an array of values per key
     * 
     * The example value above becomes:
     *       "key1" : ["valueA"],
     *       "key2" : ["valueB"],
     *       "key3" : ["valueC", "valueD", "valueE"]
     * 
     * @param authorisedTokenPermissions
     * @return
     */
    private Map<String, List<String>> readTokenPermissions(String authorisedTokenPermissions) {
        if (StringUtils.isBlank(authorisedTokenPermissions)) {
            return Collections.emptyMap();
        }
        return Stream.of(authorisedTokenPermissions.trim().split(" "))
                .map(pair -> pair.split("="))
                .filter(s -> s.length == 2) // Ignore invalid key/value pairs
                .collect(Collectors.toMap(s -> s[0], s -> Arrays.asList(s[1].split(","))));
    }
}
