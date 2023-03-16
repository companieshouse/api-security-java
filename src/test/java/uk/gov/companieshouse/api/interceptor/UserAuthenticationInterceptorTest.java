package uk.gov.companieshouse.api.interceptor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;

import uk.gov.companieshouse.api.util.security.EricConstants;

@ExtendWith(MockitoExtension.class)
@TestInstance(Lifecycle.PER_CLASS)
class UserAuthenticationInterceptorTest {

    @InjectMocks
    UserAuthenticationInterceptor userAuthenticationInterceptor;

    @Mock
    InternalUserInterceptor internalUserInterceptor;

    @Mock
    HttpServletRequest request;

    @Mock
    HttpServletResponse response;

    @Mock
    Object handler;

    @BeforeEach
    void setup() {
        List<String> methods = Arrays.asList("GET");
        List<String> types = Arrays.asList("oauth2");
        userAuthenticationInterceptor = new UserAuthenticationInterceptor(methods, types, internalUserInterceptor);

        MockitoAnnotations.initMocks(this);
    }

    @Test
    void internalMethodCallsInternalUser() throws IOException {
        when(request.getMethod()).thenReturn("PUT");
        when(internalUserInterceptor.preHandle(request, response, handler)).thenReturn(false);

        assertFalse(userAuthenticationInterceptor.preHandle(request, response, handler));
    }

    @Test
    void internalMethodCallsSuperAndHasInternalRole() throws IOException {
        when(request.getMethod()).thenReturn("PUT");
        when(internalUserInterceptor.preHandle(request, response, handler)).thenReturn(true);

        assertTrue(userAuthenticationInterceptor.preHandle(request, response, handler));
    }

    @Test
    void externalMethodKeyNotInternal() throws IOException {
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader(EricConstants.ERIC_IDENTITY)).thenReturn("asdc");
        when(request.getHeader(EricConstants.ERIC_IDENTITY_TYPE)).thenReturn("key");

        assertTrue(userAuthenticationInterceptor.preHandle(request, response, handler));
    }

    @Test
    void externalMethodOtherAuthNotInternal() throws IOException {
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader(EricConstants.ERIC_IDENTITY)).thenReturn("asdc");
        when(request.getHeader(EricConstants.ERIC_IDENTITY_TYPE)).thenReturn("oauth2");

        assertTrue(userAuthenticationInterceptor.preHandle(request, response, handler));
    }

    @Test
    void externalMethodInListAuthNoIdentity() throws IOException {
        lenient().when(request.getMethod()).thenReturn("GET");
        lenient().when(request.getHeader(EricConstants.ERIC_IDENTITY_TYPE)).thenReturn("key");

        assertFalse(userAuthenticationInterceptor.preHandle(request, response, handler));
    }

    @Test
    void externalMethodNotInListAuthNotInternal() throws IOException {
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader(EricConstants.ERIC_IDENTITY)).thenReturn("asdc");
        when(request.getHeader(EricConstants.ERIC_IDENTITY_TYPE)).thenReturn("asdc");

        assertFalse(userAuthenticationInterceptor.preHandle(request, response, handler));
    }
}
