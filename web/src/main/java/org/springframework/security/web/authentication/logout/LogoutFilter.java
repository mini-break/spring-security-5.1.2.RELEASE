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

package org.springframework.security.web.authentication.logout;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

/**
 * LogoutFilter被设计用于检测用户退出登录请求,执行相应的处理工作以及退出登录后的页面跳转
 * 
 * Logs a principal out.
 * <p>
 * Polls a series of {@link LogoutHandler}s. The handlers should be specified in the order
 * they are required. Generally you will want to call logout handlers
 * <code>TokenBasedRememberMeServices</code> and <code>SecurityContextLogoutHandler</code>
 * (in that order).
 * <p>
 * After logout, a redirect will be performed to the URL determined by either the
 * configured <tt>LogoutSuccessHandler</tt> or the <tt>logoutSuccessUrl</tt>, depending on
 * which constructor was used.
 *
 * @author Ben Alex
 * @author Eddú Meléndez
 */
public class LogoutFilter extends GenericFilterBean {

	// ~ Instance fields
	// ================================================================================================

	private RequestMatcher logoutRequestMatcher;

	private final LogoutHandler handler;
	private final LogoutSuccessHandler logoutSuccessHandler;

	// ~ Constructors
	// ===================================================================================================

	/**
	 * 缺省情况下，这里的LogoutSuccessHandler是一个SimpleUrlLogoutSuccessHandler实例，
	 * 在退出登录成功时跳转到/
	 *
	 * 安全配置信息中还会包含对cookie,remember me 等安全机制的配置，这些机制中在用户成功退出
	 * 登录时也会执行一些相应的清场工作，这些工作就是通过参数handlers传递进来的。这些handlers
	 * 中最核心的一个就是SecurityContextLogoutHandler,它会销毁session和针对当前请求的
	 * SecurityContextHolder中的安全上下文对象，这是真正意义上的退出登录
	 *
	 * Constructor which takes a <tt>LogoutSuccessHandler</tt> instance to determine the
	 * target destination after logging out. The list of <tt>LogoutHandler</tt>s are
	 * intended to perform the actual logout functionality (such as clearing the security
	 * context, invalidating the session, etc.).
	 */
	public LogoutFilter(LogoutSuccessHandler logoutSuccessHandler,
			LogoutHandler... handlers) {
		this.handler = new CompositeLogoutHandler(handlers);
		Assert.notNull(logoutSuccessHandler, "logoutSuccessHandler cannot be null");
		this.logoutSuccessHandler = logoutSuccessHandler;
		/**
		 * 定义一个缺省的用户退出登录请求匹配器：
		 * 	只要用户请求/logout而无论http method是什么，都认为是要退出登录了,
		 *  该缺省值通常会被安全配置覆盖，请留意
		 */
		setFilterProcessesUrl("/logout");
	}

	/**
	 * 另外一个构造函数，如果没有指定logoutSuccessHandler,而是只指定了logoutSuccessUrl,
	 * 该方法会根据logoutSuccessUrl构造一个logoutSuccessHandler：SimpleUrlLogoutSuccessHandler
	 */
	public LogoutFilter(String logoutSuccessUrl, LogoutHandler... handlers) {
		this.handler = new CompositeLogoutHandler(handlers);
		Assert.isTrue(
				!StringUtils.hasLength(logoutSuccessUrl)
						|| UrlUtils.isValidRedirectUrl(logoutSuccessUrl),
				() -> logoutSuccessUrl + " isn't a valid redirect URL");
		SimpleUrlLogoutSuccessHandler urlLogoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
		if (StringUtils.hasText(logoutSuccessUrl)) {
			urlLogoutSuccessHandler.setDefaultTargetUrl(logoutSuccessUrl);
		}
		logoutSuccessHandler = urlLogoutSuccessHandler;
		setFilterProcessesUrl("/logout");
	}

	// ~ Methods
	// ========================================================================================================

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		if (requiresLogout(request, response)) {
			// 检测到用户请求了退出当前登录,现在执行退出登录逻辑
			Authentication auth = SecurityContextHolder.getContext().getAuthentication();

			if (logger.isDebugEnabled()) {
				logger.debug("Logging out user '" + auth
						+ "' and transferring to logout destination");
			}

			this.handler.logout(request, response, auth);

			/**
			 * 缺省情况下，这里的LogoutSuccessHandler是一个SimpleUrlLogoutSuccessHandler实例，
			 * 在退出登录成功时跳转到/。
			 * 上面已经成功退出了用户登录，现在跳转到相应的页面
			 */
			logoutSuccessHandler.onLogoutSuccess(request, response, auth);

			/**
			 * 注意,这里完成了用户退出登录动作和页面跳转，所以当前请求的处理任务已经结束,
			 * 也就是说不用再继续filter chain的执行了，直接函数返回即可
			 */
			return;
		}

		// 不是用户请求退出登录的情况，继续执行 filter chain
		chain.doFilter(request, response);
	}

	/**
	 * 根据当前请求和安全配置检测是否用户在请求退出登录，如果是用户在请求退出登录的情况返回true，
	 * 否则返回false
	 *
	 * Allow subclasses to modify when a logout should take place.
	 *
	 * @param request the request
	 * @param response the response
	 *
	 * @return <code>true</code> if logout should occur, <code>false</code> otherwise
	 */
	protected boolean requiresLogout(HttpServletRequest request,
			HttpServletResponse response) {
		return logoutRequestMatcher.matches(request);
	}

	/**
	 * 配置阶段会将用户明确指定的logoutRequestMatcher或者根据其他配置计算出来的logoutRequestMatcher
	 * 通过该方法设置到当前Filter对象
	 */
	public void setLogoutRequestMatcher(RequestMatcher logoutRequestMatcher) {
		Assert.notNull(logoutRequestMatcher, "logoutRequestMatcher cannot be null");
		this.logoutRequestMatcher = logoutRequestMatcher;
	}

	/**
	 * 调用该方法则会将当前Filter的logoutRequestMatcher设置为一个根据filterProcessesUrl计算出来的
	 * AntPathRequestMatcher,该matcher会仅根据请求url进行匹配，而不管http method是什么
	 *
	 * 在该Filter的构造函数中就调用了该方法setFilterProcessesUrl("/logout"),从而构建了一个缺省的
	 * AntPathRequestMatcher,表示只要用户访问 url /logout,不管http method是什么，都认为用户想要
	 * 退出登录。但实际上，该初始值都会被配置过程中根据用户配置信息计算出的AntPathRequestMatcher
	 * 调用上面的setLogoutRequestMatcher(logoutRequestMatcher)覆盖该matcher
	 */
	public void setFilterProcessesUrl(String filterProcessesUrl) {
		this.logoutRequestMatcher = new AntPathRequestMatcher(filterProcessesUrl);
	}
}
