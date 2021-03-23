package uk.gov.companieshouse.api.interceptor;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import uk.gov.companieshouse.api.util.security.InvalidTokenPermissionException;
import uk.gov.companieshouse.api.util.security.TokenPermissions;

@ExtendWith(MockitoExtension.class)
@TestInstance(Lifecycle.PER_CLASS)
class TokenPermissionsInterceptorTest {
    private static final Object HANDLER = null;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private TokenPermissions tokenPermissions;

    @Spy
    private TokenPermissionsInterceptor interceptor = new TokenPermissionsInterceptor();

    @Test
    @DisplayName("Test that the preHandle method sets a TokenPermissions object in the request")
    void preHandle() throws Exception {
        doReturn(tokenPermissions).when(interceptor).readTokenPermissions(request);

        assertTrue(interceptor.preHandle(request, response, HANDLER));

        verify(request).setAttribute("token_permissions", tokenPermissions);
    }

    @Test
    @DisplayName("Test that the preHandle method throws an exception when the token permission string is invalid")
    void preHandleThrowsException() throws Exception {
        doThrow(new InvalidTokenPermissionException("invalid")).when(interceptor).readTokenPermissions(request);

        assertThrows(InvalidTokenPermissionException.class, () -> interceptor.preHandle(request, response, HANDLER));
    }

    @Test
    @DisplayName("Test that the postHandle method removes the TokenPermissions object from the request")
    void postHandle() throws Exception {

        interceptor.postHandle(request, response, HANDLER, null);

        verify(request).setAttribute("token_permissions", null);
    }
}
