package org.apache.shiro.spring.boot.kisso.authz;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.baomidou.kisso.SSOAuthorization;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link KissoAuthorizationFilter}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("KissoAuthorizationFilter Tests")
class KissoAuthorizationFilterTest {

    @Test
    @DisplayName("Instance can be created")
    void testInstantiation() {
        KissoAuthorizationFilter filter = new KissoAuthorizationFilter();
        assertThat(filter).isNotNull();
    }

    @Test
    @DisplayName("Default authorization is not null")
    void testDefaultAuthorization() {
        KissoAuthorizationFilter filter = new KissoAuthorizationFilter();
        assertThat(filter.getAuthorization()).isNotNull();
    }

    @Test
    @DisplayName("authorization getter/setter works correctly")
    void testAuthorizationGetterSetter() {
        KissoAuthorizationFilter filter = new KissoAuthorizationFilter();
        SSOAuthorization auth = mock(SSOAuthorization.class);
        filter.setAuthorization(auth);
        assertThat(filter.getAuthorization()).isSameAs(auth);
    }

    @Test
    @DisplayName("init and destroy do not throw exceptions")
    void testInitDestroy() throws ServletException {
        KissoAuthorizationFilter filter = new KissoAuthorizationFilter();
        filter.init(null);
        filter.destroy();
    }

    @Test
    @DisplayName("doFilter handles no SSO token")
    void testDoFilterNoToken() throws IOException, ServletException {
        KissoAuthorizationFilter filter = new KissoAuthorizationFilter();
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        HttpServletResponse mockResponse = mock(HttpServletResponse.class);
        FilterChain mockChain = mock(FilterChain.class);
        when(mockResponse.getOutputStream()).thenReturn(new jakarta.servlet.ServletOutputStream() {
            @Override public void write(int b) {}
            @Override public boolean isReady() { return true; }
            @Override public void setWriteListener(jakarta.servlet.WriteListener l) {}
        });

        when(mockRequest.getCookies()).thenReturn(null);

        filter.doFilter(mockRequest, mockResponse, mockChain);
    }

    @Test
    @DisplayName("doFilter throws ServletException for non-HTTP request")
    void testDoFilterNonHttp() {
        KissoAuthorizationFilter filter = new KissoAuthorizationFilter();
        assertThatThrownBy(() -> filter.doFilter(
                mock(jakarta.servlet.ServletRequest.class),
                mock(jakarta.servlet.ServletResponse.class),
                mock(FilterChain.class)))
                .isInstanceOf(ServletException.class);
    }
}
