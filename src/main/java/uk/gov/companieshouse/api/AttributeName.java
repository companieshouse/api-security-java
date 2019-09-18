package uk.gov.companieshouse.api;

public enum AttributeName {

    TRANSACTION("transaction");

    private String value;

    AttributeName(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
