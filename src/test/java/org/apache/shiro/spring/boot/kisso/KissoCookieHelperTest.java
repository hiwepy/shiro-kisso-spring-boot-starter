package org.apache.shiro.spring.boot.kisso;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.baomidou.kisso.security.token.SSOToken;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link KissoCookieHelper}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("KissoCookieHelper Tests")
class KissoCookieHelperTest {

    @Test
    @DisplayName("clearLogin adds cookie with maxAge 0")
    void testClearLogin() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.isSecure()).thenReturn(false);

        KissoCookieHelper.clearLogin(request, response);

        verify(response).addCookie(any(Cookie.class));
    }

    @Test
    @DisplayName("setCookie adds cookie with token value")
    void testSetCookie() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.isSecure()).thenReturn(false);

        SSOToken ssoToken = SSOToken.create().setId("user123");

        KissoCookieHelper.setCookie(request, response, ssoToken, false);

        verify(response).addCookie(any(Cookie.class));
    }

    @Test
    @DisplayName("setCookie with cookieMaxAge=true adds cookie with max age")
    void testSetCookieWithMaxAge() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.isSecure()).thenReturn(true);

        SSOToken ssoToken = SSOToken.create().setId("user123");

        KissoCookieHelper.setCookie(request, response, ssoToken, true);

        verify(response).addCookie(any(Cookie.class));
    }
}
