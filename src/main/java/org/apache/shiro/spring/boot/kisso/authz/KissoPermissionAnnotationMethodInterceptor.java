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
package org.apache.shiro.spring.boot.kisso.authz;

import org.apache.shiro.aop.AnnotationResolver;
import org.apache.shiro.authz.aop.AuthorizingAnnotationMethodInterceptor;

/**
 * Method interceptor for Kisso {@link Permission} annotations.
 * <p>Intercepts method invocations annotated with Kisso permission annotations
 * and delegates authorization checks to the {@link KissoPermissionAnnotationHandler}.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
public class KissoPermissionAnnotationMethodInterceptor extends AuthorizingAnnotationMethodInterceptor {

	public KissoPermissionAnnotationMethodInterceptor() {
		super(new KissoPermissionAnnotationHandler());
	}

	public KissoPermissionAnnotationMethodInterceptor(AnnotationResolver resolver) {
		super(new KissoPermissionAnnotationHandler(), resolver);
	}

}