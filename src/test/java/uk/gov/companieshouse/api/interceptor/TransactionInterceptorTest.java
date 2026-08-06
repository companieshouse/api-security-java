package uk.gov.companieshouse.api.interceptor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.servlet.HandlerMapping;
import uk.gov.companieshouse.api.ApiClient;
import uk.gov.companieshouse.api.error.ApiErrorResponseException;
import uk.gov.companieshouse.api.handler.exception.URIValidationException;
import uk.gov.companieshouse.api.handler.transaction.TransactionsResourceHandler;
import uk.gov.companieshouse.api.handler.transaction.request.TransactionsGet;
import uk.gov.companieshouse.api.model.ApiResponse;
import uk.gov.companieshouse.api.model.transaction.Transaction;
import uk.gov.companieshouse.api.sdk.ApiClientService;

@ExtendWith(MockitoExtension.class)
@TestInstance(Lifecycle.PER_CLASS)
class TransactionInterceptorTest {

    @InjectMocks
    private TransactionInterceptor transactionInterceptor = new TransactionInterceptor();

    @Mock
    private ApiClientService apiClientServiceMock;

    @Mock
    private ApiClient apiClientMock;

    @Mock
    private TransactionsResourceHandler transactionResourceHandlerMock;

    @Mock
    private TransactionsGet transactionGetMock;

    @Mock
    private HttpServletRequest httpServletRequestMock;

    @Mock
    private HttpServletResponse httpServletResponseMock;

    @Mock
    private ApiResponse<Transaction> apiResponse;

    @BeforeEach
    void setUp() throws IOException {
        Map<String, String> pathVariables = new HashMap<>();
        pathVariables.put("transactionId", "5555");

        when(httpServletRequestMock.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE))
            .thenReturn(pathVariables);
        when(httpServletRequestMock.getHeader("ERIC-Access-Token")).thenReturn("1111");

        httpServletResponseMock.setContentType("text/html");

        when(apiClientServiceMock.getApiClient(anyString())).thenReturn(apiClientMock);
    }

    private void stubTransactionChain() throws URIValidationException, IOException {
        when(apiClientMock.transactions()).thenReturn(transactionResourceHandlerMock);
        when(transactionResourceHandlerMock.get(anyString())).thenReturn(transactionGetMock);
        when(transactionGetMock.execute()).thenReturn(apiResponse);
    }

    @Test
    @DisplayName("Tests the interceptor with an existing transaction")
    void testPreHandleExistingTransaction() throws URIValidationException, IOException {
        stubTransactionChain();
        when(apiResponse.getData()).thenReturn(new Transaction());

        assertTrue(transactionInterceptor
            .preHandle(httpServletRequestMock, httpServletResponseMock, new Object()));
    }

    @Test
    @DisplayName("Tests the interceptor constructed with a logging namespace")
    void testConstructorWithLoggingNamespace() throws URIValidationException, IOException {
        stubTransactionChain();
        when(apiResponse.getData()).thenReturn(new Transaction());

        TransactionInterceptor interceptorWithNamespace = new TransactionInterceptor("test.namespace");
        interceptorWithNamespace.setApiClientService(apiClientServiceMock);

        assertTrue(interceptorWithNamespace
            .preHandle(httpServletRequestMock, httpServletResponseMock, new Object()));
    }

    @Test
    @DisplayName("Tests the interceptor returns false and sets status on HttpClientErrorException")
    void testPreHandleHttpClientErrorException() throws URIValidationException, IOException {
        stubTransactionChain();
        HttpClientErrorException exception = HttpClientErrorException.create(
                HttpStatus.NOT_FOUND, "Not Found", null, null, null);
        when(transactionGetMock.execute()).thenThrow(exception);

        assertFalse(transactionInterceptor
            .preHandle(httpServletRequestMock, httpServletResponseMock, new Object()));
        verify(httpServletResponseMock).setStatus(HttpStatus.NOT_FOUND.value());
    }

    @Test
    @DisplayName("Tests the interceptor returns false and sets status on ApiErrorResponseException")
    void testPreHandleApiErrorResponseException() throws URIValidationException, IOException {
        stubTransactionChain();
        ApiErrorResponseException exception = new ApiErrorResponseException(
                new com.google.api.client.http.HttpResponseException.Builder(
                        503, "Service Unavailable", new com.google.api.client.http.HttpHeaders()));
        when(transactionGetMock.execute()).thenThrow(exception);

        assertFalse(transactionInterceptor
            .preHandle(httpServletRequestMock, httpServletResponseMock, new Object()));
        verify(httpServletResponseMock).setStatus(503);
    }

    @Test
    @DisplayName("Tests the interceptor returns false and sets 500 on URIValidationException")
    void testPreHandleURIValidationException() throws URIValidationException, IOException {
        stubTransactionChain();
        when(transactionGetMock.execute()).thenThrow(new URIValidationException("bad uri"));

        assertFalse(transactionInterceptor
            .preHandle(httpServletRequestMock, httpServletResponseMock, new Object()));
        verify(httpServletResponseMock).setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
    }

    @Test
    @DisplayName("Tests the interceptor returns false and sets 500 on IOException")
    void testPreHandleIOException() throws URIValidationException, IOException {
        when(apiClientServiceMock.getApiClient(anyString())).thenThrow(new IOException("io error"));

        assertFalse(transactionInterceptor
            .preHandle(httpServletRequestMock, httpServletResponseMock, new Object()));
        verify(httpServletResponseMock).setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
    }
}
