/*
 * Copyright (c) 2018 (https://github.com/hiwepy).
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
package org.apache.shiro.spring.boot.kisso.exception;

import org.apache.shiro.authc.AuthenticationException;

/**
 * Exception thrown when a URI access is not permitted.
 * <p>Extends {@link AuthenticationException} to indicate that the requested
 * URI does not have sufficient permissions in the Kisso authorization check.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class URIUnpermittedException extends AuthenticationException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 5804347841925337928L;

	public URIUnpermittedException() {
		super();
	}

	public URIUnpermittedException(String message, Throwable cause) {
		super(message, cause);
	}

	public URIUnpermittedException(String message) {
		super(message);
	}

	public URIUnpermittedException(Throwable cause) {
		super(cause);
	}
}
