package uk.gov.companieshouse.api.interceptor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Arrays;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import uk.gov.companieshouse.api.util.security.EricConstants;

@ExtendWith(MockitoExtension.class)
@TestInstance(Lifecycle.PER_CLASS)
class UserAuthenticationInterceptorTest {

    UserAuthenticationInterceptor userAuthenticationInterceptor;

    @Mock
    HttpServletRequest request;

    @Mock
    HttpServletResponse response;

    @Mock
    Object handler;

    @BeforeEach
    void setup() {
        userAuthenticationInterceptor = new UserAuthenticationInterceptor(Arrays.asList("GET"), Arrays.asList("oauth2"));
    }

    @Test
    void internalMethodCallsSuper() throws IOException {
        when(request.getMethod()).thenReturn("PUT");
        when(request.getHeader(EricConstants.ERIC_IDENTITY)).thenReturn("asdc");
        when(request.getHeader(EricConstants.ERIC_IDENTITY_TYPE)).thenReturn("key");

        assertFalse(userAuthenticationInterceptor.preHandle(request, response, userAuthenticationInterceptor));
    }

    @Test
    void internalMethodCallsSuperAndHasInternalRole() throws IOException {
        when(request.getMethod()).thenReturn("PUT");
        when(request.getHeader(EricConstants.ERIC_IDENTITY)).thenReturn("asdc");
        when(request.getHeader(EricConstants.ERIC_IDENTITY_TYPE)).thenReturn("key");
        when(request.getHeader(EricConstants.ERIC_AUTHORISED_KEY_ROLES)).thenReturn("*");

        assertTrue(userAuthenticationInterceptor.preHandle(request, response, userAuthenticationInterceptor));
    }

    @Test
    void externalMethodKeyNotInternal() throws IOException {
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader(EricConstants.ERIC_IDENTITY)).thenReturn("asdc");
        when(request.getHeader(EricConstants.ERIC_IDENTITY_TYPE)).thenReturn("key");

        assertTrue(userAuthenticationInterceptor.preHandle(request, response, userAuthenticationInterceptor));
    }

    @Test
    void externalMethodOtherAuthNotInternal() throws IOException {
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader(EricConstants.ERIC_IDENTITY)).thenReturn("asdc");
        when(request.getHeader(EricConstants.ERIC_IDENTITY_TYPE)).thenReturn("oauth2");

        assertTrue(userAuthenticationInterceptor.preHandle(request, response, userAuthenticationInterceptor));
    }

    @Test
    void externalMethodInListAuthNoIdentity() throws IOException {
        lenient().when(request.getMethod()).thenReturn("GET");
        lenient().when(request.getHeader(EricConstants.ERIC_IDENTITY_TYPE)).thenReturn("key");

        assertFalse(userAuthenticationInterceptor.preHandle(request, response, userAuthenticationInterceptor));
    }

    @Test
    void externalMethodNotInListAuthNotInternal() throws IOException {
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader(EricConstants.ERIC_IDENTITY)).thenReturn("asdc");
        when(request.getHeader(EricConstants.ERIC_IDENTITY_TYPE)).thenReturn("asdc");

        assertFalse(userAuthenticationInterceptor.preHandle(request, response, userAuthenticationInterceptor));
    }
}
