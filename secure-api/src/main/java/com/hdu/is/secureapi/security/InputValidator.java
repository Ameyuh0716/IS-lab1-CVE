package com.hdu.is.secureapi.security;

import java.util.regex.Pattern;

/**
 * Allow-list validation of user-controlled identifiers before they reach any query or log sink.
 * This is a second line of defence on top of parameterized queries.
 */
public final class InputValidator {

    private static final Pattern USERNAME = Pattern.compile("^[A-Za-z0-9_.-]{3,32}$");
    private static final Pattern SEARCH_TERM = Pattern.compile("^[\\p{L}\\p{N} _.-]{0,64}$");

    private InputValidator() {
    }

    public static boolean isValidUsername(String username) {
        return username != null && USERNAME.matcher(username).matches();
    }

    public static boolean isValidSearchTerm(String term) {
        return term != null && SEARCH_TERM.matcher(term).matches();
    }
}
