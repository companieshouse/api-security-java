package uk.gov.companieshouse.api.util.security;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TokenPermissionsFormatTest {

    @ParameterizedTest
    @ValueSource(strings = {
            "user_profile=read",
            "user_profile=create,read,update,delete",
            "company_number=00001234 user_profile=read",
            "a=b c=d,e,f"
    })
    void acceptsValidPermissionHeaderFormats(String header) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("ERIC-Authorised-Token-Permissions")).thenReturn(header);

        assertDoesNotThrow(() -> new TokenPermissionsImpl(request));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "invalid",
            "user_profile=",
            "=read",
            "user-profile=read",     // hyphen not allowed by \\w
            "user_profile=read,",    // trailing comma
            "user_profile=read  company_number=1", // double space
            " user_profile=read",    // leading space
            "user_profile=read "     // trailing space
    })
    void rejectsInvalidPermissionHeaderFormats(String header) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("ERIC-Authorised-Token-Permissions")).thenReturn(header);

        assertThrows(InvalidTokenPermissionException.class, () -> new TokenPermissionsImpl(request));
    }
}