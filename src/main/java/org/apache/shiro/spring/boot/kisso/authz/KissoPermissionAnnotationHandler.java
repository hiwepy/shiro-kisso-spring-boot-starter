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

import java.lang.annotation.Annotation;

import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.aop.AuthorizingAnnotationHandler;

import com.baomidou.kisso.annotation.Permission;

/**
 * TODO
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class KissoPermissionAnnotationHandler extends AuthorizingAnnotationHandler {

	public KissoPermissionAnnotationHandler() {
		super(Permission.class);
	}

	@Override
	public void assertAuthorized(Annotation a) throws AuthorizationException {
		Permission pm = (Permission) a;
		if (pm != null) {
            if (pm.ignore()) {
                // 忽略检查
            } else {
                // 权限检查
            	getSubject().checkPermissions(pm.value());
            }
        }
	}

}
