package uk.gov.companieshouse.api.interceptor;

import java.util.HashMap;
import java.util.Map;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;
import uk.gov.companieshouse.api.AttributeName;
import uk.gov.companieshouse.api.model.transaction.Transaction;
import uk.gov.companieshouse.api.model.transaction.TransactionStatus;
import uk.gov.companieshouse.logging.Logger;
import uk.gov.companieshouse.logging.LoggerFactory;

public class ClosedTransactionInterceptor implements HandlerInterceptor {

    private final Logger LOGGER;


    public ClosedTransactionInterceptor() {
        LOGGER = LoggerFactory.getLogger(String.valueOf(ClosedTransactionInterceptor.class));
    }

    public ClosedTransactionInterceptor(String loggingNamespace) {
        LOGGER = LoggerFactory.getLogger(loggingNamespace);
    }

    /**
     * Pre handle method to validate the request before it reaches the controller by checking if
     * transaction's status is closed.
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response,
        Object handler) {
        Transaction transaction = (Transaction) request
            .getAttribute(AttributeName.TRANSACTION.getValue());

        if (transaction == null || !TransactionStatus.CLOSED.getStatus()
            .equalsIgnoreCase(transaction.getStatus().getStatus())) {
            final Map<String, Object> debugMap = new HashMap<>();
            debugMap.put("request_method", request.getMethod());

            LOGGER.errorRequest(request, "ClosedTransactionInterceptor error: no closed transaction available", debugMap);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return false;
        }
        return true;
    }
}