package org.apache.shiro.spring.boot.kisso.authc;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link KissoAuthenticatingFilter}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("KissoAuthenticatingFilter Tests")
class KissoAuthenticatingFilterTest {

    @Test
    @DisplayName("Instance can be created")
    void testInstantiation() {
        KissoAuthenticatingFilter filter = new KissoAuthenticatingFilter();
        assertThat(filter).isNotNull();
    }

    @Test
    @DisplayName("Default handlerInterceptor is KissoDefaultHandler")
    void testDefaultHandlerInterceptor() {
        KissoAuthenticatingFilter filter = new KissoAuthenticatingFilter();
        assertThat(filter.getHandlerInterceptor()).isNotNull();
    }

    @Test
    @DisplayName("handlerInterceptor getter/setter works correctly")
    void testHandlerInterceptorGetterSetter() {
        KissoAuthenticatingFilter filter = new KissoAuthenticatingFilter();
        com.baomidou.kisso.web.handler.SSOHandlerInterceptor interceptor = mock(com.baomidou.kisso.web.handler.SSOHandlerInterceptor.class);
        filter.setHandlerInterceptor(interceptor);
        assertThat(filter.getHandlerInterceptor()).isSameAs(interceptor);
    }

    @Test
    @DisplayName("init and destroy do not throw exceptions")
    void testInitDestroy() throws ServletException {
        KissoAuthenticatingFilter filter = new KissoAuthenticatingFilter();
        filter.init(null);
        filter.destroy();
    }

    @Test
    @DisplayName("doFilter passes through when no SSO token present")
    void testDoFilterNoToken() throws IOException, ServletException {
        KissoAuthenticatingFilter filter = new KissoAuthenticatingFilter();
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        HttpServletResponse mockResponse = mock(HttpServletResponse.class);
        FilterChain mockChain = mock(FilterChain.class);

        when(mockRequest.getCookies()).thenReturn(null);

        filter.doFilter(mockRequest, mockResponse, mockChain);
        verify(mockChain).doFilter(mockRequest, mockResponse);
    }

    @Test
    @DisplayName("doFilter throws ServletException for non-HTTP request")
    void testDoFilterNonHttp() {
        KissoAuthenticatingFilter filter = new KissoAuthenticatingFilter();
        assertThatThrownBy(() -> filter.doFilter(
                mock(jakarta.servlet.ServletRequest.class),
                mock(jakarta.servlet.ServletResponse.class),
                mock(FilterChain.class)))
                .isInstanceOf(ServletException.class);
    }
}
