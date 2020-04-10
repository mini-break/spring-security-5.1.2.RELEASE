/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.web.authentication;

import java.io.IOException;
import java.util.*;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * 此过滤器过滤请求,检测SecurityContextHolder中是否存在Authentication对象，
 * 如果不存在，说明用户尚未登录，此时为其提供一个匿名Authentication对象:AnonymousAuthentication
 *
 * Detects if there is no {@code Authentication} object in the
 * {@code SecurityContextHolder}, and populates it with one if needed.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public class AnonymousAuthenticationFilter extends GenericFilterBean implements
		InitializingBean {

	// ~ Instance fields
	// ================================================================================================

	/**
	 * 用于构造匿名Authentication中详情属性的详情来源对象，这里使用一个WebAuthenticationDetailsSource
	 */
	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
	private String key;
	private Object principal;
	private List<GrantedAuthority> authorities;

	/**
	 * 使用外部指定的key构造一个AnonymousAuthenticationFilter:
	 * 	1. 缺省情况下，Spring Security 配置机制为这里指定的key是一个随机的uuid;
	 * 	2. 所对应的 principal(含义指当前登录主体) 是一个字符串"anonymousUser";
	 * 	3. 所拥护的角色是 "ROLE_ANONYMOUS";
	 *
	 * Creates a filter with a principal named "anonymousUser" and the single authority
	 * "ROLE_ANONYMOUS".
	 *
	 * @param key the key to identify tokens created by this filter
	 */
	public AnonymousAuthenticationFilter(String key) {
		this(key, "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
	}

	/**
	 * 使用外部指定的参数构造一个AnonymousAuthenticationFilter
	 * 
	 * @param key key the key to identify tokens created by this filter
	 * @param principal the principal which will be used to represent anonymous users
	 * @param authorities the authority list for anonymous users
	 */
	public AnonymousAuthenticationFilter(String key, Object principal,
			List<GrantedAuthority> authorities) {
		Assert.hasLength(key, "key cannot be null or empty");
		Assert.notNull(principal, "Anonymous authentication principal must be set");
		Assert.notNull(authorities, "Anonymous authorities must be set");
		this.key = key;
		this.principal = principal;
		this.authorities = authorities;
	}

	// ~ Methods
	// ========================================================================================================

	@Override
	public void afterPropertiesSet() {
		// 在当前Filter bean被创建时调用，主要目的是断言三个主要属性都必须已经有效设置
		Assert.hasLength(key, "key must have length");
		Assert.notNull(principal, "Anonymous authentication principal must be set");
		Assert.notNull(authorities, "Anonymous authorities must be set");
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {

		if (SecurityContextHolder.getContext().getAuthentication() == null) {
			/**
			 * 如果SecurityContextHolder中SecurityContext对象的属性authentication是null,
			 * 将其替换成一个匿名 Authentication: AnonymousAuthentication
			 */
			SecurityContextHolder.getContext().setAuthentication(
					createAuthentication((HttpServletRequest) req));

			if (logger.isDebugEnabled()) {
				logger.debug("Populated SecurityContextHolder with anonymous token: '"
						+ SecurityContextHolder.getContext().getAuthentication() + "'");
			}
		}
		else {
			if (logger.isDebugEnabled()) {
				logger.debug("SecurityContextHolder not populated with anonymous token, as it already contained: '"
						+ SecurityContextHolder.getContext().getAuthentication() + "'");
			}
		}

		chain.doFilter(req, res);
	}

	/**
	 * 根据指定属性key,princpial,authorities和当前环境(servlet web环境)构造一个AnonymousAuthenticationToken
	 */
	protected Authentication createAuthentication(HttpServletRequest request) {
		AnonymousAuthenticationToken auth = new AnonymousAuthenticationToken(key,
				principal, authorities);
		auth.setDetails(authenticationDetailsSource.buildDetails(request));

		return auth;
	}

	/**
	 * 可以外部指定Authentication对象的详情来源, 缺省情况下使用的是WebAuthenticationDetailsSource,
	 * 已经在属性authenticationDetailsSource初始化指定
	 */
	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource,
				"AuthenticationDetailsSource required");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	public Object getPrincipal() {
		return principal;
	}

	public List<GrantedAuthority> getAuthorities() {
		return authorities;
	}
}
