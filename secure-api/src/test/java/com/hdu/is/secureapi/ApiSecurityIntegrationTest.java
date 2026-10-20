package com.hdu.is.secureapi;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest
@AutoConfigureMockMvc
class ApiSecurityIntegrationTest {

    private static final String VALID_CREDENTIALS = """
            {"username":"alice","password":"Alice@Passw0rd"}""";

    @Autowired
    private MockMvc mockMvc;

    private String login(String body) throws Exception {
        MvcResult result = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn();
        // Read the token with a small regex so the test does not depend on a specific Jackson version.
        var matcher = java.util.regex.Pattern.compile("\"token\"\\s*:\\s*\"([^\"]+)\"").matcher(
                result.getResponse().getContentAsString());
        assertThat(matcher.find()).as("login response must contain a token").isTrue();
        return matcher.group(1);
    }

    @Test
    void loginReturnsJwtForValidCredentials() throws Exception {
        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(VALID_CREDENTIALS))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"));
    }

    @Test
    void loginFailsWithWrongPassword() throws Exception {
        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"alice","password":"wrong"}"""))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void protectedEndpointRejectsAnonymousRequest() throws Exception {
        mockMvc.perform(get("/api/data"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void protectedEndpointRejectsTamperedToken() throws Exception {
        String token = login(VALID_CREDENTIALS);
        String tampered = token.substring(0, token.length() - 2) + "aa";

        mockMvc.perform(get("/api/data").header(HttpHeaders.AUTHORIZATION, "Bearer " + tampered))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void protectedEndpointAcceptsValidToken() throws Exception {
        String token = login(VALID_CREDENTIALS);

        mockMvc.perform(get("/api/data").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].passwordHash").doesNotExist());
    }

    @Test
    void sqlInjectionPayloadInSearchIsTreatedAsData() throws Exception {
        String token = login(VALID_CREDENTIALS);

        mockMvc.perform(get("/api/posts")
                        .param("q", "' OR 1=1 --")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isBadRequest());

        mockMvc.perform(get("/api/posts")
                        .param("q", "JWT")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1));
    }

    @Test
    void sqlInjectionPayloadInLoginIsTreatedAsData() throws Exception {
        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"alice' OR '1'='1","password":"x"}"""))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void xssPayloadIsEscapedBeforeStorage() throws Exception {
        String token = login(VALID_CREDENTIALS);

        MvcResult created = mockMvc.perform(post("/api/posts")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"title":"<script>alert(1)</script>","body":"<img src=x onerror=alert(1)>"}"""))
                .andExpect(status().isCreated())
                .andReturn();

        String body = created.getResponse().getContentAsString();
        assertThat(body).doesNotContain("<script>").doesNotContain("<img");
        assertThat(body).contains("&lt;script&gt;");
    }

    @Test
    void customEndpointDescribesAuthenticatedIdentity() throws Exception {
        String token = login(VALID_CREDENTIALS);

        mockMvc.perform(get("/api/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("alice")));
    }

    @Test
    void nonAdminCannotDeletePost() throws Exception {
        String token = login(VALID_CREDENTIALS);

        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .delete("/api/posts/1")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isForbidden());
    }
}
