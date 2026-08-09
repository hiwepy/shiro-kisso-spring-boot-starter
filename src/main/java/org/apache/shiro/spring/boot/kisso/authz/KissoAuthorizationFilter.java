package org.apache.shiro.spring.boot.kisso.authz;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.authc.AuthcResponse;
import org.apache.shiro.biz.web.servlet.http.HttpStatus;
import org.apache.shiro.spring.boot.kisso.exception.URIUnpermittedException;
import org.apache.shiro.spring.boot.kisso.token.KissoAccessToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;

import com.alibaba.fastjson.JSONObject;
import com.baomidou.kisso.SSOAuthorization;
import com.baomidou.kisso.SSOConfig;
import com.baomidou.kisso.common.auth.AuthDefaultImpl;
import com.baomidou.kisso.security.token.SSOToken;
import org.apache.shiro.spring.boot.kisso.KissoTokenExtractor;

/**
 * Authorization filter for Kisso SSO authentication.
 * <p>Performs URI permission checks using Kisso's authorization mechanism,
 * then delegates to Shiro's subject.login() for authentication. Handles
 * both stateless (AJAX) and stateful (redirect) authorization failure modes.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
public class KissoAuthorizationFilter implements Filter {

	private static final Logger LOG = LoggerFactory.getLogger(KissoAuthorizationFilter.class);
	/*
     * 系统权限授权接口
     */
    private SSOAuthorization authorization = new AuthDefaultImpl();

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		// no-op
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
			throws IOException, ServletException {

		if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
			throw new ServletException("just supports HTTP requests");
		}

		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;

		try {
			// Step 1、 获取当前请求 Kisso Token
			SSOToken ssoToken = KissoTokenExtractor.getSSOToken(httpRequest);
			if (ssoToken == null) {
				handleUnauthorized(request, response, "No SSO token found.");
				return;
			}

			/*
	         * Step 2、URL 权限认证
			 */
			if (SSOConfig.getInstance().isPermissionUri()) {
				String uri = httpRequest.getRequestURI();
				if (!(uri == null || this.getAuthorization().isPermitted(ssoToken, uri))) {
					throw new URIUnpermittedException("URI Unpermitted Access.");
				}
			}

			// Step 3、生成Token
			AuthenticationToken actoken = new KissoAccessToken(httpRequest.getRemoteAddr(), ssoToken);

			// Step 4、委托给Realm进行登录
			Subject subject = SecurityUtils.getSubject();
			subject.login(actoken);

			// Step 5、认证成功，继续
			filterChain.doFilter(request, response);
		} catch (AuthenticationException e) {
			LOG.error("Host {} Kisso Authentication Failure : {}", httpRequest.getRemoteAddr(), e.getMessage());

			String mString = "Attempting to access a path which requires authentication. ";
			httpResponse.setStatus(HttpStatus.SC_OK);
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			response.setCharacterEncoding(StandardCharsets.UTF_8.name());

			if (e instanceof URIUnpermittedException) {
				JSONObject.writeJSONString(response.getOutputStream(), AuthcResponse.fail("URI Unpermitted Access."));
			} else {
				JSONObject.writeJSONString(response.getOutputStream(), AuthcResponse.fail(HttpStatus.SC_FORBIDDEN, mString));
			}
		}
	}

	@Override
	public void destroy() {
		// no-op
	}

	private void handleUnauthorized(ServletRequest request, ServletResponse response, String message)
			throws IOException {
		HttpServletResponse httpResponse = (HttpServletResponse) response;
		httpResponse.setStatus(HttpStatus.SC_OK);
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());
		JSONObject.writeJSONString(response.getOutputStream(), AuthcResponse.fail(HttpStatus.SC_UNAUTHORIZED, message));
	}

	/**
	 * Returns the SSO authorization implementation.
	 *
	 * @return the SSO authorization
	 */
	public SSOAuthorization getAuthorization() {
		return authorization;
	}

	/**
	 * Sets the SSO authorization implementation.
	 *
	 * @param authorization the SSO authorization
	 */
	public void setAuthorization(SSOAuthorization authorization) {
		this.authorization = authorization;
	}

}
