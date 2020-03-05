package uk.gov.companieshouse.api.interceptor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import uk.gov.companieshouse.api.util.security.EricConstants;
import uk.gov.companieshouse.api.util.security.SecurityConstants;

@ExtendWith(MockitoExtension.class)
@TestInstance(Lifecycle.PER_CLASS)
class InternalUserInterceptorTest {
    
    private static final Object NO_HANDLER = null;
    
    @Mock
    private HttpServletRequest mockRequest;

    @Mock
    private HttpServletResponse mockResponse;
    
    private InternalUserInterceptor internalUserInterceptor = new InternalUserInterceptor();

    
    @Test
    @DisplayName("Test that Handler allows a user with the correct privilege through")
    public void testUserHasCorrectPriviledges() throws IOException {
        doReturn("test user").when(mockRequest).getHeader(EricConstants.ERIC_IDENTITY);
        doReturn(SecurityConstants.API_KEY_IDENTITY_TYPE).when(mockRequest).getHeader(EricConstants.ERIC_IDENTITY_TYPE);
        doReturn(SecurityConstants.INTERNAL_USER_ROLE).when(mockRequest).getHeader(EricConstants.ERIC_AUTHORISED_KEY_ROLES);
        assertTrue(internalUserInterceptor.preHandle(mockRequest, mockResponse, NO_HANDLER));
    }
    
    @Test
    @DisplayName("Test that Handler stops a request when no user is passed from Eric")
    public void testNoUser() throws IOException {
        assertFalse(internalUserInterceptor.preHandle(mockRequest, mockResponse, NO_HANDLER));
    }
    
    @Test
    @DisplayName("Test that Handler stops a request when not from an API User")
    public void testNotAPIUser() throws IOException {
        doReturn("test user").when(mockRequest).getHeader(EricConstants.ERIC_IDENTITY);
        doReturn("OAUTH").when(mockRequest).getHeader(EricConstants.ERIC_IDENTITY_TYPE);
        assertFalse(internalUserInterceptor.preHandle(mockRequest, mockResponse, NO_HANDLER));
    }
    
    @Test
    @DisplayName("Test that Handler stops a request when API user does not have internal privileges")
    public void testNoInternalPriviledges() throws IOException {
        doReturn("test user").when(mockRequest).getHeader(EricConstants.ERIC_IDENTITY);
        doReturn(SecurityConstants.API_KEY_IDENTITY_TYPE).when(mockRequest).getHeader(EricConstants.ERIC_IDENTITY_TYPE);
        doReturn("Yellow").when(mockRequest).getHeader(EricConstants.ERIC_AUTHORISED_KEY_ROLES);
        assertFalse(internalUserInterceptor.preHandle(mockRequest, mockResponse, NO_HANDLER));
    }

}
