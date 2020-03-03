package uk.gov.companieshouse.api.util.security;

public class InvalidTokenPermissionException extends Exception {
    private static final long serialVersionUID = -8911200210133036075L;
    
    private final String authorisedTokenPermissions;

    public InvalidTokenPermissionException(String authorisedTokenPermissions) {
        this.authorisedTokenPermissions = authorisedTokenPermissions;
    }

    public String getAuthorisedTokenPermissions() {
        return authorisedTokenPermissions;
    }
}
