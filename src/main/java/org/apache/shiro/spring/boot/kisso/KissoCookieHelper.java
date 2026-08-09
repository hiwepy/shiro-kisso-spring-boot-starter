package org.apache.shiro.spring.boot.kisso;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.baomidou.kisso.SSOConfig;
import com.baomidou.kisso.security.token.SSOToken;

/**
 * Utility to manage Kisso SSO cookies using Jakarta Servlet API.
 * <p>Bridges the gap between Jakarta Servlet API (used by Spring Boot 4.1)
 * and Kisso's javax.servlet-based cookie handling.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
public final class KissoCookieHelper {

	private KissoCookieHelper() {
		// utility class
	}

	/**
	 * Sets the SSO token as a cookie in the response.
	 *
	 * @param request the Jakarta servlet request
	 * @param response the Jakarta servlet response
	 * @param ssoToken the SSO token to set
	 * @param cookieMaxAge if true, use configured max age; if false, use session cookie
	 */
	public static void setCookie(HttpServletRequest request, HttpServletResponse response,
			SSOToken ssoToken, boolean cookieMaxAge) {
		SSOConfig config = SSOConfig.getInstance();
		String cookieName = config.getCookieName();
		String tokenValue = ssoToken.getToken();

		Cookie cookie = new Cookie(cookieName, tokenValue);
		cookie.setPath(config.getCookiePath());
		cookie.setHttpOnly(true);
		cookie.setSecure(request.isSecure());

		if (config.getCookieDomain() != null && !config.getCookieDomain().isEmpty()) {
			cookie.setDomain(config.getCookieDomain());
		}

		if (cookieMaxAge && config.getCookieMaxAge() > 0) {
			cookie.setMaxAge(config.getCookieMaxAge());
		} else {
			cookie.setMaxAge(-1);
		}

		response.addCookie(cookie);
	}

	/**
	 * Clears the SSO login cookie.
	 *
	 * @param request the Jakarta servlet request
	 * @param response the Jakarta servlet response
	 */
	public static void clearLogin(HttpServletRequest request, HttpServletResponse response) {
		SSOConfig config = SSOConfig.getInstance();
		String cookieName = config.getCookieName();

		Cookie cookie = new Cookie(cookieName, "");
		cookie.setPath(config.getCookiePath());
		cookie.setMaxAge(0);
		cookie.setHttpOnly(true);

		if (config.getCookieDomain() != null && !config.getCookieDomain().isEmpty()) {
			cookie.setDomain(config.getCookieDomain());
		}

		response.addCookie(cookie);
	}

}
