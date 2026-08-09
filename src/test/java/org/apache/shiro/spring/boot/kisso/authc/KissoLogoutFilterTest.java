package org.apache.shiro.spring.boot.kisso.authc;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link KissoLogoutFilter}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("KissoLogoutFilter Tests")
class KissoLogoutFilterTest {

    @Test
    @DisplayName("Instance can be created")
    void testInstantiation() {
        KissoLogoutFilter filter = new KissoLogoutFilter();
        assertThat(filter).isNotNull();
    }

    @Test
    @DisplayName("init and destroy do not throw exceptions")
    void testInitDestroy() throws ServletException {
        KissoLogoutFilter filter = new KissoLogoutFilter();
        filter.init(null);
        filter.destroy();
    }

    @Test
    @DisplayName("doFilter performs logout and clears cookies")
    void testDoFilter() throws IOException, ServletException {
        KissoLogoutFilter filter = new KissoLogoutFilter();
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        HttpServletResponse mockResponse = mock(HttpServletResponse.class);
        FilterChain mockChain = mock(FilterChain.class);

        SecurityManager sm = mock(SecurityManager.class);
        Subject subject = mock(Subject.class);
        ThreadContext.bind(sm);
        ThreadContext.bind(subject);

        try {
            filter.doFilter(mockRequest, mockResponse, mockChain);
            verify(subject).logout();
            verify(mockChain).doFilter(mockRequest, mockResponse);
        } finally {
            ThreadContext.remove();
        }
    }
}
