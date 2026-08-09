package org.apache.shiro.spring.boot.kisso;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link KissoTokenExtractor}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("KissoTokenExtractor Tests")
class KissoTokenExtractorTest {

    @Test
    @DisplayName("getSSOToken returns null when no cookies")
    void testGetSSOTokenNoCookies() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getCookies()).thenReturn(null);
        assertThat(KissoTokenExtractor.getSSOToken(request)).isNull();
    }

    @Test
    @DisplayName("getSSOToken returns null when empty cookies")
    void testGetSSOTokenEmptyCookies() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getCookies()).thenReturn(new Cookie[]{});
        assertThat(KissoTokenExtractor.getSSOToken(request)).isNull();
    }

    @Test
    @DisplayName("getSSOToken returns null when no matching cookie")
    void testGetSSOTokenNoMatchingCookie() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        Cookie cookie = new Cookie("other", "value");
        when(request.getCookies()).thenReturn(new Cookie[]{cookie});
        assertThat(KissoTokenExtractor.getSSOToken(request)).isNull();
    }
}
