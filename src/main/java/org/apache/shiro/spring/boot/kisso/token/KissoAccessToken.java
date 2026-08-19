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
package org.apache.shiro.spring.boot.kisso.token;

import org.apache.shiro.authc.HostAuthenticationToken;

import com.baomidou.kisso.security.token.SSOToken;

/**
 * Authentication token wrapping a Kisso {@link SSOToken} for stateless authentication.
 * <p>Implements {@link HostAuthenticationToken} to carry the client host information
 * along with the SSO token for authentication.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@SuppressWarnings("serial")
public class KissoAccessToken implements HostAuthenticationToken {

	// 客户端IP
	private String host;
	// SSO Token 令牌
	private SSOToken token;
	
	public KissoAccessToken(String host, SSOToken token) {
		this.host = host;
		this.token = token;
	}

	@Override
	/**
	 * Returns the principal.
	 *
	 * @return the principal
	 */
	public Object getPrincipal() {
		return this.token;
	}

	@Override
	/**
	 * Returns the credentials.
	 *
	 * @return the credentials
	 */
	public Object getCredentials() {
		return this.token;
	}
	
	@Override
	/**
	 * Returns the host.
	 *
	 * @return the host
	 */
	public String getHost() {
		return host;
	}

	/**
	 * Returns the token.
	 *
	 * @return the token
	 */
	public SSOToken getToken() {
		return token;
	}
	
}
