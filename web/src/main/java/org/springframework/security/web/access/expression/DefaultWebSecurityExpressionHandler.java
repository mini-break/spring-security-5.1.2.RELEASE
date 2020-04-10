/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.access.expression;

import org.springframework.security.access.expression.AbstractSecurityExpressionHandler;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.util.Assert;

/**
 * DefaultWebSecurityExpressionHandler是Spring Security Web用于Web安全表达式处理器(handler)。
 * 它会基于一组缺省配置，和当前的环境，对指定的Web安全表达式求值
 * 
 * @author Luke Taylor
 * @author Eddú Meléndez
 * @since 3.0
 */
public class DefaultWebSecurityExpressionHandler extends
		AbstractSecurityExpressionHandler<FilterInvocation> implements
		SecurityExpressionHandler<FilterInvocation> {

	/**
	 * 用于识别一个Authentication对象是否 anonymous, rememberMe
	 * 缺省使用AuthenticationTrustResolverImpl
	 */
	private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
	/**
	 * 缺省使用的角色前缀
	 */
	private String defaultRolePrefix = "ROLE_";

	/**
	 * 对给定的认证token authentication 和给定的请求上下文 fi 构建 SecurityExpressionOperations，
	 * 此 SecurityExpressionOperations 用于进一步构建 EvaluationContext 对象
	 */
	@Override
	protected SecurityExpressionOperations createSecurityExpressionRoot(
			Authentication authentication, FilterInvocation fi) {
		WebSecurityExpressionRoot root = new WebSecurityExpressionRoot(authentication, fi);
		root.setPermissionEvaluator(getPermissionEvaluator());
		root.setTrustResolver(trustResolver);
		root.setRoleHierarchy(getRoleHierarchy());
		root.setDefaultRolePrefix(this.defaultRolePrefix);
		return root;
	}

	/**
	 * Sets the {@link AuthenticationTrustResolver} to be used. The default is
	 * {@link AuthenticationTrustResolverImpl}.
	 *
	 * @param trustResolver the {@link AuthenticationTrustResolver} to use. Cannot be
	 * null.
	 */
	public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
		Assert.notNull(trustResolver, "trustResolver cannot be null");
		this.trustResolver = trustResolver;
	}

	/**
	 * 设置表达式hasAnyRole(String...)或者hasRole(String)使用的角色前缀。不调用该方法，则使用缺省值 "ROLE_"。
	 * 如果调用了该方法，设置参数为 null 或者 "", 表明不使用角色前缀。
	 *
	 * <p>
	 * Sets the default prefix to be added to {@link org.springframework.security.access.expression.SecurityExpressionRoot#hasAnyRole(String...)} or
	 * {@link org.springframework.security.access.expression.SecurityExpressionRoot#hasRole(String)}. For example, if hasRole("ADMIN") or hasRole("ROLE_ADMIN")
	 * is passed in, then the role ROLE_ADMIN will be used when the defaultRolePrefix is
	 * "ROLE_" (default).
	 * </p>
	 *
	 * <p>
	 * If null or empty, then no default role prefix is used.
	 * </p>
	 *
	 * @param defaultRolePrefix the default prefix to add to roles. Default "ROLE_".
	 */
	public void setDefaultRolePrefix(String defaultRolePrefix) {
		this.defaultRolePrefix = defaultRolePrefix;
	}
}
