package uk.gov.companieshouse.api.interceptor;
import org.springframework.web.servlet.HandlerInterceptor;
import uk.gov.companieshouse.api.AttributeName;
import uk.gov.companieshouse.api.model.transaction.Transaction;
import uk.gov.companieshouse.api.model.transaction.TransactionStatus;
import uk.gov.companieshouse.logging.Logger;
import uk.gov.companieshouse.logging.LoggerFactory;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

public class OpenTransactionInterceptor implements HandlerInterceptor {

    private final Logger LOGGER;


    public OpenTransactionInterceptor() {
        LOGGER = LoggerFactory.getLogger(String.valueOf(OpenTransactionInterceptor.class));
    }

    public OpenTransactionInterceptor(String loggingNamespace) {
        LOGGER = LoggerFactory.getLogger(loggingNamespace);
    }
    /**
     * Pre handle method to validate the request before it reaches the controller by checking if the
     * request is a GET request and if the transaction's status is open.
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        Transaction transaction = (Transaction) request.getAttribute(AttributeName.TRANSACTION.getValue());

        String requestMethod = request.getMethod();

        if (transaction == null ||
            (!requestMethod.equals("GET") && !TransactionStatus.OPEN.getStatus()
                .equalsIgnoreCase(transaction.getStatus().getStatus()))) {
            final Map<String, Object> debugMap = new HashMap<>();
            debugMap.put("request_method", request.getMethod());

            LOGGER.errorRequest(request, "OpenTransactionInterceptor error: no open transaction available", debugMap);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return false;
        }

        return true;
    }
}