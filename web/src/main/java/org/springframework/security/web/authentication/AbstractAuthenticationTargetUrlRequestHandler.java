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
package org.springframework.security.web.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * 认证动作成功时使用一个跳转策略跳转到指定的URL
 * 
 * Base class containing the logic used by strategies which handle redirection to a URL
 * and are passed an {@code Authentication} object as part of the contract. See
 * {@link AuthenticationSuccessHandler} and
 * {@link org.springframework.security.web.authentication.logout.LogoutSuccessHandler
 * LogoutSuccessHandler}, for example.
 * <p>
 * Uses the following logic sequence to determine how it should handle the
 * forward/redirect
 * <ul>
 * <li>
 * If the {@code alwaysUseDefaultTargetUrl} property is set to true, the
 * {@code defaultTargetUrl} property will be used for the destination.</li>
 * <li>
 * If a parameter matching the value of {@code targetUrlParameter} has been set on the
 * request, the value will be used as the destination. If you are enabling this
 * functionality, then you should ensure that the parameter cannot be used by an attacker
 * to redirect the user to a malicious site (by clicking on a URL with the parameter
 * included, for example). Typically it would be used when the parameter is included in
 * the login form and submitted with the username and password.</li>
 * <li>
 * If the {@code useReferer} property is set, the "Referer" HTTP header value will be
 * used, if present.</li>
 * <li>
 * As a fallback option, the {@code defaultTargetUrl} value will be used.</li>
 * </ul>
 *
 * @author Luke Taylor
 * @since 3.0
 */
public abstract class AbstractAuthenticationTargetUrlRequestHandler {

	protected final Log logger = LogFactory.getLog(this.getClass());
	/**
	 * 如果通过请求参数指定跳转目标URL，使用此属性指定相应的参数名称，可以设置，
	 * 缺省值为 null， 表示不分析请求参数中指定的跳转目标URL
	 */
	private String targetUrlParameter = null;
	/**
	 * 缺省跳转目标 URL，可以设置, 缺省值一般使用"/"
	 */
	private String defaultTargetUrl = "/";
	/**
	 * 是否总是使用缺省跳转目标 URL，也就是属性 defaultTargetUrl ，可以设置,缺省值一般使用 false
	 */
	private boolean alwaysUseDefaultTargetUrl = false;
	/**
	 * 是否使用头部 Referer ，可以设置,缺省值一般使用 false
	 */
	private boolean useReferer = false;
	/**
	 * 跳转策略，可以设置,缺省使用 DefaultRedirectStrategy
	 */
	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	protected AbstractAuthenticationTargetUrlRequestHandler() {
	}

	/**
	 * Invokes the configured {@code RedirectStrategy} with the URL returned by the
	 * {@code determineTargetUrl} method.
	 * <p>
	 * The redirect will not be performed if the response has already been committed.
	 */
	protected void handle(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		// 计算跳转目标URL : targetUrl
		String targetUrl = determineTargetUrl(request, response);

		if (response.isCommitted()) {
			// 如果响应对象已经提交，则什么都不做，输出debug日志后直接返回
			logger.debug("Response has already been committed. Unable to redirect to "
					+ targetUrl);
			return;
		}

		// 使用指定的跳转策略跳转到目标url :  targetUrl 
		redirectStrategy.sendRedirect(request, response, targetUrl);
	}

	/**
	 * Builds the target URL according to the logic defined in the main class Javadoc.
	 */
	protected String determineTargetUrl(HttpServletRequest request,
			HttpServletResponse response) {
		// 如果被设置要求总是使用缺省跳转目标url，则返回缺省跳转目标url : defaultTargetUrl
		if (isAlwaysUseDefaultTargetUrl()) {
			return defaultTargetUrl;
		}

		// Check for the parameter and use that if available
		String targetUrl = null;

		// 如果属性  targetUrlParameter 不为 null， 说明被设置成需要从请求参数中分析跳转目标url
		if (targetUrlParameter != null) {
			targetUrl = request.getParameter(targetUrlParameter);

			if (StringUtils.hasText(targetUrl)) {
				// 如果从请求参数中分析得到跳转目标url，返回该url
				logger.debug("Found targetUrlParameter in request: " + targetUrl);

				return targetUrl;
			}
		}

		/**
		 * 如果被设置为要使用请求头部 Referer 模式，并且目标 url 尚未分析得到，
		 * 则尝试从请求头部 Referer 获取跳转目标url
		 */
		if (useReferer && !StringUtils.hasLength(targetUrl)) {
			targetUrl = request.getHeader("Referer");
			logger.debug("Using Referer header: " + targetUrl);
		}

		/**
		 * 如果经过以上各种分析逻辑，仍未确定跳转目标url，则跳转目标url使用缺省跳转url，
		 * 也就是 defaultTargetUrl
		 */
		if (!StringUtils.hasText(targetUrl)) {
			targetUrl = defaultTargetUrl;
			logger.debug("Using default Url: " + targetUrl);
		}

		return targetUrl;
	}

	/**
	 * Supplies the default target Url that will be used if no saved request is found or
	 * the {@code alwaysUseDefaultTargetUrl} property is set to true. If not set, defaults
	 * to {@code /}.
	 *
	 * @return the defaultTargetUrl property
	 */
	protected final String getDefaultTargetUrl() {
		return defaultTargetUrl;
	}

	/**
	 * 设置默认url
	 * Supplies the default target Url that will be used if no saved request is found in
	 * the session, or the {@code alwaysUseDefaultTargetUrl} property is set to true. If
	 * not set, defaults to {@code /}. It will be treated as relative to the web-app's
	 * context path, and should include the leading <code>/</code>. Alternatively,
	 * inclusion of a scheme name (such as "http://" or "https://") as the prefix will
	 * denote a fully-qualified URL and this is also supported.
	 *
	 * @param defaultTargetUrl
	 */
	public void setDefaultTargetUrl(String defaultTargetUrl) {
		Assert.isTrue(UrlUtils.isValidRedirectUrl(defaultTargetUrl),
				"defaultTarget must start with '/' or with 'http(s)'");
		this.defaultTargetUrl = defaultTargetUrl;
	}

	/**
	 * If <code>true</code>, will always redirect to the value of {@code defaultTargetUrl}
	 * (defaults to <code>false</code>).
	 */
	public void setAlwaysUseDefaultTargetUrl(boolean alwaysUseDefaultTargetUrl) {
		this.alwaysUseDefaultTargetUrl = alwaysUseDefaultTargetUrl;
	}

	protected boolean isAlwaysUseDefaultTargetUrl() {
		return alwaysUseDefaultTargetUrl;
	}

	/**
	 * If this property is set, the current request will be checked for this a parameter
	 * with this name and the value used as the target URL if present.
	 *
	 * @param targetUrlParameter the name of the parameter containing the encoded target
	 * URL. Defaults to null.
	 */
	public void setTargetUrlParameter(String targetUrlParameter) {
		if (targetUrlParameter != null) {
			Assert.hasText(targetUrlParameter, "targetUrlParameter cannot be empty");
		}
		this.targetUrlParameter = targetUrlParameter;
	}

	protected String getTargetUrlParameter() {
		return targetUrlParameter;
	}

	/**
	 * Allows overriding of the behaviour when redirecting to a target URL.
	 */
	public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
		this.redirectStrategy = redirectStrategy;
	}

	protected RedirectStrategy getRedirectStrategy() {
		return redirectStrategy;
	}

	/**
	 * If set to {@code true} the {@code Referer} header will be used (if available).
	 * Defaults to {@code false}.
	 */
	public void setUseReferer(boolean useReferer) {
		this.useReferer = useReferer;
	}

}
