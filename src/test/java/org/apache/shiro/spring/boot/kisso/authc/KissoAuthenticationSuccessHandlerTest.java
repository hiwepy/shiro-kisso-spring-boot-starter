package org.apache.shiro.spring.boot.kisso.authc;

import org.apache.shiro.spring.boot.kisso.token.KissoLoginToken;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link KissoAuthenticationSuccessHandler}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("KissoAuthenticationSuccessHandler Tests")
class KissoAuthenticationSuccessHandlerTest {

    @Test
    @DisplayName("Instance can be created")
    void testInstantiation() {
        KissoAuthenticationSuccessHandler handler = new KissoAuthenticationSuccessHandler();
        assertThat(handler).isNotNull();
    }

    @Test
    @DisplayName("getOrder returns expected value")
    void testGetOrder() {
        KissoAuthenticationSuccessHandler handler = new KissoAuthenticationSuccessHandler();
        assertThat(handler.getOrder()).isEqualTo(Integer.MAX_VALUE - 2);
    }

    @Test
    @DisplayName("supports returns true for KissoLoginToken")
    void testSupportsKissoLoginToken() {
        KissoAuthenticationSuccessHandler handler = new KissoAuthenticationSuccessHandler();
        assertThat(handler.supports(new KissoLoginToken())).isTrue();
    }

    @Test
    @DisplayName("supports returns false for non-KissoLoginToken")
    void testSupportsNonKissoToken() {
        KissoAuthenticationSuccessHandler handler = new KissoAuthenticationSuccessHandler();
        assertThat(handler.supports(new org.apache.shiro.authc.UsernamePasswordToken("u", "p"))).isFalse();
    }
}
