package uk.gov.companieshouse.api.sdk.impl;

import java.io.IOException;
import org.springframework.stereotype.Component;
import uk.gov.companieshouse.api.ApiClient;
import uk.gov.companieshouse.api.InternalApiClient;
import uk.gov.companieshouse.api.sdk.ApiClientService;
import uk.gov.companieshouse.sdk.manager.ApiSdkManager;

@Component
public class ApiClientServiceImpl implements ApiClientService {

    @Override
    public ApiClient getApiClient() {
        return ApiSdkManager.getSDK();
    }

    @Override
    public ApiClient getApiClient(String passthroughHeader) throws IOException {
        return ApiSdkManager.getSDK(passthroughHeader);
    }

    @Override
    public InternalApiClient getInternalApiClient() {
        return ApiSdkManager.getPrivateSDK();
    }

    @Override
    public InternalApiClient getInternalApiClient(String passthroughHeader) throws IOException {
        return ApiSdkManager.getPrivateSDK(passthroughHeader);
    }
}
