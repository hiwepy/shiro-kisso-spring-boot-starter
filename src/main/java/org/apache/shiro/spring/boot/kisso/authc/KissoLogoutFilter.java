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

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.spring.boot.kisso.KissoCookieHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Logout filter for Kisso SSO authentication.
 * <p>Clears both Shiro session state and Kisso SSO cookie data
 * upon logout.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class KissoLogoutFilter implements Filter {

    private static final Logger LOG = LoggerFactory.getLogger(KissoLogoutFilter.class);

	@Override
	/**
	 * init.
	 *
	 * @param filterConfig the filter config
	 * @throws ServletException if an error occurs
	 */
	public void init(FilterConfig filterConfig) throws ServletException {
		// no-op
	}

	@Override
	/**
	 * do Filter.
	 *
	 * @param request the request
	 * @param response the response
	 * @param filterChain the filter chain
	 */
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
			throws IOException, ServletException {

		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;

		try {
			Subject subject = SecurityUtils.getSubject();
			subject.logout();
			KissoCookieHelper.clearLogin(httpRequest, httpResponse);
		} catch (Exception e) {
			LOG.debug("Encountered session exception during logout.  This can generally safely be ignored.", e);
		}

		filterChain.doFilter(request, response);
	}

	@Override
	/**
	 * destroy.
	 *
	 */
	public void destroy() {
		// no-op
	}

}
