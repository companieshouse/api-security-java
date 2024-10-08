package uk.gov.companieshouse.api.util.security;

public class Permission {

    public enum Key {
        /**
         * Key for the user profile permissions permissions
         */
        USER_PROFILE("user_profile"),
        /**
         * Key for the user transactions permissions
         */
        USER_TRANSACTIONS("user_transactions"),
        /**
         * Key for the user follow permissions
         */
        USER_FOLLOWING("user_following"),
        /**
         * Key for the user application/api client permissions
         */
        USER_APPLICATIONS("user_applications"),
        /**
         * Key for the user secure application/api client permissions
         */
        USER_SECURE_APPLICATIONS("user_secure_applications"),
        /**
         * Key for the user orders permissions
         */
        USER_ORDERS("user_orders"),
        /**
         * Key for the user auth code request permissions
         */
        USER_REQUEST_AUTH_CODE("user_request_auth_code"),
        /**
         * Key for the user presenter account permissions
         */
        USER_PRESENTER("user_presenter"),
        /**
         * Key for the detailing the company number for any company level permissions
         */
        COMPANY_NUMBER("company_number"),
        /**
         * Key for the company status permissions
         */
        COMPANY_STATUS("company_status"),
        /**
         * Key for the company transactions permissions
         */
        COMPANY_TRANSACTIONS("company_transactions"),
        /**
         * Key for the company auth code permissions
         */
        COMPANY_AUTH_CODE("company_auth_code"),
        /**
         * Key for company registered office address (ROA) permissions
         */
        COMPANY_ROA("company_roa"),
        /**
         * Key for company accounts (annual accounts filing) permissions
         */
        COMPANY_ACCOUNTS("company_accounts"),
        /**
         * Key for promise to file permissions
         */
        PROMISE_TO_FILE("company_promise_to_file"),
        /**
         * Key for psc discrepancy reports permissions
         */
        USER_PSC_DISCREPANCY_REPORT("user_psc_discrepancy_report"),
        /**
         * Key for confirmation statement permissions
         */
        COMPANY_CONFIRMATION_STATEMENT("company_confirmation_statement"),
        /**
         * Key for overseas entity permissions
         */
        COMPANY_INCORPORATION("company_incorporation"),
        /**
         * Key for company officers permissions
         */
        COMPANY_OFFICERS("company_officers"),
        /**
         * Key for company PSC permissions
         */
        COMPANY_PSCS("company_pscs"),
        /**
         * Key for company REA update permissions
         */
        COMPANY_REA_UPDATE("company_rea"),

        /**
         * Key for OE Annual Updates (ROE Update)
         */
        COMPANY_OE_ANNUAL_UPDATE("company_oe_annual_update"),

        /**
         * Key for Acsp the user is a member of
         */
        ACSP_NUMBER("acsp_number"),

        /**
         * Key for user's permissible actions on owners
         */
        ACSP_MEMBERS_OWNERS("acsp_members_owners"),

        /**
         * Key for user's permissible actions on admins
         */
        ACSP_MEMBERS_ADMINS("acsp_members_admins"),

        /**
         * Key for user's permissible actions on standard users
         */
        ACSP_MEMBERS_STANDARD("acsp_members_standard"),

        /**
         * Key for user's permission to retrieve data related to an Acsp
         */
        ACSP_MEMBERS("acsp_members"),

        /**
         * Key for user verification permission
         */
        USER_PSC_VERIFICATION("user_psc_verification");

        private final String stringValue;

        Key(final String permissionKey) {
            stringValue = permissionKey;
        }

        @Override
        public String toString() {
            return stringValue;
        }
    }
    
    public static class Value {
        /**
         * Value for resource creation permissions
         */
        public static final String CREATE = "create";
        /**
         * Value for resource reading permissions
         */
        public static final String READ = "read";
        /**
         * Value for resource accessing protected data
         */
        public static final String READ_PROTECTED = "readprotected";
        /**
         * Value for resource updating permissions
         */
        public static final String UPDATE = "update";
        /**
         * Value for resource deletion permissions
         */
        public static final String DELETE = "delete";
        
        private Value() {
            // Hide implicit public constructor
        }
    }

}
