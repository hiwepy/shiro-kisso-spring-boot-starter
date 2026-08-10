package org.apache.shiro.spring.boot.kisso.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link URIUnpermittedException}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("URIUnpermittedException Tests")
class URIUnpermittedExceptionTest {

    @Test
    @DisplayName("Default constructor")
    void testDefault() {
        URIUnpermittedException ex = new URIUnpermittedException();
        assertThat(ex).isNotNull();
    }

    @Test
    @DisplayName("Constructor with message")
    void testMessage() {
        URIUnpermittedException ex = new URIUnpermittedException("not permitted");
        assertThat(ex).hasMessage("not permitted");
    }

    @Test
    @DisplayName("Constructor with message and cause")
    void testMessageCause() {
        RuntimeException cause = new RuntimeException("root");
        URIUnpermittedException ex = new URIUnpermittedException("not permitted", cause);
        assertThat(ex).hasMessage("not permitted");
        assertThat(ex.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Constructor with cause")
    void testCause() {
        RuntimeException cause = new RuntimeException("root");
        URIUnpermittedException ex = new URIUnpermittedException(cause);
        assertThat(ex.getCause()).isEqualTo(cause);
    }
}
