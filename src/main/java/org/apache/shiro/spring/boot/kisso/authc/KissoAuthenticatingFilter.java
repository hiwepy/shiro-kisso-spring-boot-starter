/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.spring.boot.kisso.authc;

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
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;

import com.alibaba.fastjson.JSONObject;
import com.baomidou.kisso.common.SSOConstants;
import com.baomidou.kisso.security.token.SSOToken;
import com.baomidou.kisso.web.handler.KissoDefaultHandler;
import com.baomidou.kisso.web.handler.SSOHandlerInterceptor;
import org.apache.shiro.spring.boot.kisso.KissoTokenExtractor;
import org.apache.shiro.spring.boot.kisso.token.KissoAccessToken;

/**
 * Authentication filter for Kisso SSO token-based authentication.
 * <p>Intercepts requests, extracts the Kisso SSO token from cookies,
 * and delegates authentication to Shiro's subject.login() mechanism.
 * Handles both stateless and stateful authentication modes.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class KissoAuthenticatingFilter implements Filter {

	private static final Logger LOG = LoggerFactory.getLogger(KissoAuthenticatingFilter.class);
	private SSOHandlerInterceptor handlerInterceptor;

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

		// 获取当前请求 Kisso Token
		SSOToken ssoToken = KissoTokenExtractor.getSSOToken(httpRequest);
		if (ssoToken != null) {
			/*
			 * 正常请求，request 设置 token 减少二次解密
			 */
			request.setAttribute(SSOConstants.SSO_TOKEN_ATTR, ssoToken);

			// Step 1、生成Shiro Token
			AuthenticationToken token = new KissoAccessToken(httpRequest.getRemoteAddr(), ssoToken);
			try {
				// Step 2、委托给Realm进行登录
				Subject subject = SecurityUtils.getSubject();
				subject.login(token);
				// Step 3、认证成功，继续
				filterChain.doFilter(request, response);
				return;
			} catch (AuthenticationException e) {
				// Step 4、认证失败
				LOG.debug("Kisso authentication failure: {}", e.getMessage());

				HttpServletResponse httpResponse = (HttpServletResponse) response;
				httpResponse.setStatus(HttpStatus.SC_OK);
				response.setContentType(MediaType.APPLICATION_JSON_VALUE);
				response.setCharacterEncoding(StandardCharsets.UTF_8.name());
				JSONObject.writeJSONString(response.getOutputStream(), AuthcResponse.fail(HttpStatus.SC_UNAUTHORIZED, e.getMessage()));
				return;
			}
		}

		// No SSO token, pass through
		filterChain.doFilter(request, response);
	}

	@Override
	public void destroy() {
		// no-op
	}

	/**
	 * Returns the SSO handler interceptor, defaulting to {@link KissoDefaultHandler}.
	 *
	 * @return the handler interceptor
	 */
	public SSOHandlerInterceptor getHandlerInterceptor() {
        if (handlerInterceptor == null) {
            return KissoDefaultHandler.getInstance();
        }
        return handlerInterceptor;
    }

    /**
     * Sets the SSO handler interceptor.
     *
     * @param handlerInterceptor the handler interceptor
     */
    public void setHandlerInterceptor(SSOHandlerInterceptor handlerInterceptor) {
        this.handlerInterceptor = handlerInterceptor;
    }

}
