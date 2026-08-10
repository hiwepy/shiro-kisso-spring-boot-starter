package org.apache.shiro.spring.boot.kisso;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

import com.baomidou.kisso.SSOConfig;
import com.baomidou.kisso.security.token.SSOToken;

/**
 * Utility to extract Kisso SSO tokens from Jakarta Servlet requests.
 * <p>Bridges the gap between Jakarta Servlet API (used by Spring Boot 4.1)
 * and Kisso's javax.servlet-based API.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public final class KissoTokenExtractor {

	private KissoTokenExtractor() {
		// utility class
	}

	/**
	 * Extracts the SSO token from the request cookie.
	 *
	 * @param request the Jakarta servlet request
	 * @return the SSOToken, or null if not found
	 */
	public static SSOToken getSSOToken(HttpServletRequest request) {
		String cookieName = SSOConfig.getInstance().getCookieName();
		Cookie[] cookies = request.getCookies();
		if (cookies == null) {
			return null;
		}
		for (Cookie cookie : cookies) {
			if (cookieName.equals(cookie.getName())) {
				String tokenValue = cookie.getValue();
				if (tokenValue != null && !tokenValue.isEmpty()) {
					return SSOToken.parser(tokenValue);
				}
			}
		}
		return null;
	}

}
