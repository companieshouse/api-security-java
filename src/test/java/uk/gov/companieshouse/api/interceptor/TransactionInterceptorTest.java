package uk.gov.companieshouse.api.interceptor;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
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
import org.springframework.web.servlet.HandlerMapping;
import uk.gov.companieshouse.api.ApiClient;
import uk.gov.companieshouse.api.sdk.ApiClientService;
import uk.gov.companieshouse.api.handler.exception.URIValidationException;
import uk.gov.companieshouse.api.handler.transaction.TransactionsResourceHandler;
import uk.gov.companieshouse.api.handler.transaction.request.TransactionsGet;
import uk.gov.companieshouse.api.model.ApiResponse;
import uk.gov.companieshouse.api.model.transaction.Transaction;

@ExtendWith(MockitoExtension.class)
@TestInstance(Lifecycle.PER_CLASS)
public class TransactionInterceptorTest {

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
    void setUp() throws URIValidationException, IOException {
        Map<String, String> pathVariables = new HashMap<>();
        pathVariables.put("transactionId", "5555");

        when(httpServletRequestMock.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE))
            .thenReturn(pathVariables);
        when(httpServletRequestMock.getHeader("ERIC-Access-Token")).thenReturn("1111");

        httpServletResponseMock.setContentType("text/html");

        when(apiClientServiceMock.getApiClient(anyString())).thenReturn(apiClientMock);
        when(apiClientMock.transactions()).thenReturn(transactionResourceHandlerMock);
        when(transactionResourceHandlerMock.get(anyString())).thenReturn(transactionGetMock);
        when(transactionGetMock.execute()).thenReturn(apiResponse);
        when(apiResponse.getData()).thenReturn(new Transaction());
    }

    @Test
    @DisplayName("Tests the interceptor with an existing transaction")
    void testPreHandleExistingTransaction() {

        assertTrue(transactionInterceptor
            .preHandle(httpServletRequestMock, httpServletResponseMock, new Object()));
    }
}