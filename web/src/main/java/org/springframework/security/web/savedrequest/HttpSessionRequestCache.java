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
package org.springframework.security.web.savedrequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Spring Security Web认证机制(通常指表单登录)中登录成功后页面需要跳转到原来客户请求的URL。
 * 该过程中首先需要将原来的客户请求缓存下来，然后登录成功后将缓存的请求从缓存中提取出来
 * 
 * {@code RequestCache} which stores the {@code SavedRequest} in the HttpSession.
 * 将SavedRequest保存到HttpSession中的RequestCache
 *
 * The {@link DefaultSavedRequest} class is used as the implementation.
 * 这里使用的SavedRequest是其缺省实现DefaultSavedRequest
 *
 * @author Luke Taylor
 * @author Eddú Meléndez
 * @since 3.0
 */
public class HttpSessionRequestCache implements RequestCache {
	/**
	 * 将请求缓存到session时缺省使用的session属性名称
	 */
	static final String SAVED_REQUEST = "SPRING_SECURITY_SAVED_REQUEST";
	protected final Log logger = LogFactory.getLog(this.getClass());

	/**
	 * 用于解析请求中的 server:port 信息
	 */
	private PortResolver portResolver = new PortResolverImpl();
	/**
	 * 如果session不存在是否允许创建，缺省为true可以创建
	 */
	private boolean createSessionAllowed = true;
	// 用于判断哪些请求可以被缓存的请求匹配器，缺省为任何请求都可以被缓存，
	// 实际上会被外部指定覆盖成:
	// 1. 必须是 GET /**
	// 2. 并且不能是 /**/favicon.*
	// 3. 并且不能是 application.json
	// 4. 并且不能是 XMLHttpRequest (也就是一般意义上的 ajax 请求)
	private RequestMatcher requestMatcher = AnyRequestMatcher.INSTANCE;
	/**
	 * 将请求缓存到session时使用的session属性名称，初始化为使用SAVED_REQUEST
	 */
	private String sessionAttrName = SAVED_REQUEST;

	/**
	 * 在配置属性requestMatcher匹配的情况下缓存当前请求
	 * Stores the current request, provided the configuration properties allow it.
	 */
	public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
		if (requestMatcher.matches(request)) {
			/**
			 * 在配置属性requestMatcher匹配的情况下缓存当前请求，
			 * 首先将当前请求包装成一个DefaultSavedRequest,也就是从当前请求中获取
			 * 各种必要的信息组装成一个DefaultSavedRequest
			 */
			DefaultSavedRequest savedRequest = new DefaultSavedRequest(request,
					portResolver);

			/**
			 * 获取session并执行缓存动作，也就是将上面创建的DefaultSavedRequest对象
			 * 添加为session的一个名称为this.sessionAttrName的属性
			 */
			if (createSessionAllowed || request.getSession(false) != null) {
				// Store the HTTP request itself. Used by
				// AbstractAuthenticationProcessingFilter
				// for redirection after successful authentication (SEC-29)
				request.getSession().setAttribute(this.sessionAttrName, savedRequest);
				logger.debug("DefaultSavedRequest added to Session: " + savedRequest);
			}
		}
		else {
			logger.debug("Request not saved as configured RequestMatcher did not match");
		}
	}

	/**
	 * 从session中提取所缓存的请求对象，也就是获取session中名称为this.sessionAttrName的属性，
	 * 如果 session 不存在直接返回 null
	 */
	public SavedRequest getRequest(HttpServletRequest currentRequest,
			HttpServletResponse response) {
		HttpSession session = currentRequest.getSession(false);

		if (session != null) {
			return (SavedRequest) session.getAttribute(this.sessionAttrName);
		}

		return null;
	}

	/**
	 * 从 session 中删除所缓存的请求对象,也就是移除session中名称为this.sessionAttrName的属性
	 */
	public void removeRequest(HttpServletRequest currentRequest,
			HttpServletResponse response) {
		HttpSession session = currentRequest.getSession(false);

		if (session != null) {
			logger.debug("Removing DefaultSavedRequest from session if present");
			session.removeAttribute(this.sessionAttrName);
		}
	}

	/**
	 * 从 session 获取缓存的请求对象，检验它和当前请求是否一致，如果一致的话将其封装成
	 * 一个SavedRequestAwareWrapper返回，同时删除所缓存的请求。其他情况则不做任何修改动作，直接返回null
	 */
	public HttpServletRequest getMatchingRequest(HttpServletRequest request,
			HttpServletResponse response) {
		// 从 session 获取缓存的请求对象
		SavedRequest saved = getRequest(request, response);

		if (!matchesSavedRequest(request, saved)) {
			// 如果缓存的请求和当前请求不匹配则返回null
			logger.debug("saved request doesn't match");
			return null;
		}

		// 如果缓存的请求和当前请求匹配则删除缓存中缓存的请求对象
		removeRequest(request, response);

		// 封装和返回从缓存中提取到的请求对象
		return new SavedRequestAwareWrapper(saved, request);
	}

	/**
	 * 检测当前请求和参数savedRequest是否匹配
	 */
	private boolean matchesSavedRequest(HttpServletRequest request, SavedRequest savedRequest) {
		if (savedRequest == null) {
			return false;
		}

		if (savedRequest instanceof DefaultSavedRequest) {
			/**
			 * 如果savedRequest是一个DefaultSavedRequest，则使用DefaultSavedRequest的
			 * 方法doesRequestMatch检验是否匹配
			 */
			DefaultSavedRequest defaultSavedRequest = (DefaultSavedRequest) savedRequest;
			return defaultSavedRequest.doesRequestMatch(request, this.portResolver);
		}

		/**
		 * 如果savedRequest不是一个DefaultSavedRequest，则通过比较二者的url是否相等来检验二者是否匹配
		 */
		String currentUrl = UrlUtils.buildFullRequestUrl(request);
		return savedRequest.getRedirectUrl().equals(currentUrl);
	}

	/**
	 * 指定哪些请求会被缓存，如果不指定，缺省情况是所有请求都会被缓存
	 * 
	 * Allows selective use of saved requests for a subset of requests. By default any
	 * request will be cached by the {@code saveRequest} method.
	 * <p>
	 * If set, only matching requests will be cached.
	 *
	 * @param requestMatcher a request matching strategy which defines which requests
	 * should be cached.
	 */
	public void setRequestMatcher(RequestMatcher requestMatcher) {
		this.requestMatcher = requestMatcher;
	}

	/**
	 * If <code>true</code>, indicates that it is permitted to store the target URL and
	 * exception information in a new <code>HttpSession</code> (the default). In
	 * situations where you do not wish to unnecessarily create <code>HttpSession</code>s
	 * - because the user agent will know the failed URL, such as with BASIC or Digest
	 * authentication - you may wish to set this property to <code>false</code>.
	 */
	public void setCreateSessionAllowed(boolean createSessionAllowed) {
		this.createSessionAllowed = createSessionAllowed;
	}

	public void setPortResolver(PortResolver portResolver) {
		this.portResolver = portResolver;
	}

	/**
	 * If the {@code sessionAttrName} property is set, the request is stored in
	 * the session using this attribute name. Default is
	 * "SPRING_SECURITY_SAVED_REQUEST".
	 *
	 * @param sessionAttrName a new session attribute name.
	 * @since 4.2.1
	 */
	public void setSessionAttrName(String sessionAttrName) {
		this.sessionAttrName = sessionAttrName;
	}
}
