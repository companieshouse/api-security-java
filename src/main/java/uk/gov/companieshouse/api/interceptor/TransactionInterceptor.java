package uk.gov.companieshouse.api.interceptor;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.HandlerMapping;
import uk.gov.companieshouse.api.ApiClient;
import uk.gov.companieshouse.api.AttributeName;
import uk.gov.companieshouse.api.error.ApiErrorResponseException;
import uk.gov.companieshouse.api.handler.exception.URIValidationException;
import uk.gov.companieshouse.api.model.transaction.Transaction;
import uk.gov.companieshouse.api.sdk.ApiClientService;
import uk.gov.companieshouse.logging.Logger;
import uk.gov.companieshouse.logging.LoggerFactory;
import uk.gov.companieshouse.sdk.manager.ApiSdkManager;

public class TransactionInterceptor implements HandlerInterceptor {

    private final Logger logger;

    @Autowired
    private ApiClientService apiClientService;

    public TransactionInterceptor() {
        logger = LoggerFactory.getLogger(String.valueOf(TransactionInterceptor.class));
    }

    public TransactionInterceptor(String loggingNamespace) {
        logger = LoggerFactory.getLogger(loggingNamespace);
    }

    /**
     * Pre handle method to validate the request before it reaches the controller. Check if the url
     * has an existing transaction and save it in the request's attribute. If transaction is not
     * found then return 404
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response,
        Object handler) {

        final Map<String, Object> debugMap = new HashMap<>();
        debugMap.put("request_method", request.getMethod());

        try {

            Map<String, String> pathVariables = (Map) request
                .getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);

            String transactionId = pathVariables.get("transactionId");
            String passthroughHeader = request
                .getHeader(ApiSdkManager.getEricPassthroughTokenHeader());

            ApiClient apiClient = apiClientService.getApiClient(passthroughHeader);

            Transaction transaction = apiClient.transactions().get("/transactions/" + transactionId)
                .execute().getData();

            request.setAttribute(AttributeName.TRANSACTION.getValue(), transaction);
            return true;

        } catch (HttpClientErrorException e) {

            logger.errorRequest(request, e, debugMap);
            response.setStatus(e.getStatusCode().value());
            return false;

        } catch (ApiErrorResponseException e) {

            logger.errorRequest(request, e, debugMap);
            response.setStatus(e.getStatusCode());
            return false;

        } catch (URIValidationException | IOException e) {

            logger.errorRequest(request, e, debugMap);
            response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            return false;
        }
    }
}