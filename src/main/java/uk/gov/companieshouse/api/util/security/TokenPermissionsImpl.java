package uk.gov.companieshouse.api.util.security;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;

import uk.gov.companieshouse.logging.Logger;
import uk.gov.companieshouse.logging.LoggerFactory;

/**
 * Reads and stores the authorised ERIC token permissions from a request and
 * provides a method to check them individually
 */
public class TokenPermissionsImpl implements TokenPermissions {

    private static final Logger LOGGER = LoggerFactory.getLogger(String.valueOf(TokenPermissionsImpl.class));
    private static final Pattern PERMISSION_LIST_PATTERN = Pattern.compile("^\\w+=\\w+(,\\w+)*( \\w+=\\w+(,\\w+)*)*$");

    final String authorisedTokenPermissions;
    Map<String, List<String>> permissions;

    public TokenPermissionsImpl(HttpServletRequest request) throws InvalidTokenPermissionException{
        authorisedTokenPermissions = AuthorisationUtil.getAuthorisedTokenPermissions(request);
        
        if (authorisedTokenPermissions != null
                && !PERMISSION_LIST_PATTERN.matcher(authorisedTokenPermissions).matches()) {
            throw new InvalidTokenPermissionException(authorisedTokenPermissions);
        }
    }


    @Override
    public boolean hasPermission(Permission.Key key, String value) {
        if (permissions == null) {
            permissions = readTokenPermissions(authorisedTokenPermissions);
            Map<String, Object> logData = new HashMap<>();
            logData.put("ERIC authorised token permission header", authorisedTokenPermissions);
            logData.put("Token permissions", permissions);
            LOGGER.debug("Parsed ERIC token permissions", logData);
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
     * @param allPermissions
     * @return
     */
    private static Map<String, List<String>> readTokenPermissions(String allPermissions) {
        if (StringUtils.isBlank(allPermissions)) {
            return Collections.emptyMap();
        }
        return Stream.of(allPermissions.trim().split(" "))
                .map(pair -> pair.split("="))
                .collect(Collectors.toMap(s -> s[0], s -> Arrays.asList(s[1].split(","))));
    }
}
