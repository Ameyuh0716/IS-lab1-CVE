package com.hdu.is.secureapi.security;

import org.springframework.web.util.HtmlUtils;

/**
 * Context-aware output encoding for values that are persisted and later rendered by a browser.
 * Everything returned through the API is stored already escaped, so a payload such as
 * {@code <script>alert(1)</script>} is stored and returned as harmless text.
 */
public final class XssSanitizer {

    private XssSanitizer() {
    }

    public static String escape(String value) {
        return value == null ? null : HtmlUtils.htmlEscape(value, "UTF-8");
    }
}
