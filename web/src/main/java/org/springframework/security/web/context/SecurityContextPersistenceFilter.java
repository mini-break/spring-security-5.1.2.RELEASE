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
package org.springframework.security.web.context;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

/**
 * SecurityContextPersistenceFilter有两个主要任务:
 * 1.在请求到达时处理之前，从SecurityContextRepository(通常为HttpSessionSecurityContextRepository)中获取安全上下文信息填充到SecurityContextHolder
 * 2.在请求处理结束后返回响应时，将SecurityContextHolder中的安全上下文信息保存回SecurityContextRepository,并清空SecurityContextHolder
 * 跨请求安全上下文SecurityContext的保持
 *
 * Populates the {@link SecurityContextHolder} with information obtained from the
 * configured {@link SecurityContextRepository} prior to the request and stores it back in
 * the repository once the request has completed and clearing the context holder. By
 * default it uses an {@link HttpSessionSecurityContextRepository}. See this class for
 * information <tt>HttpSession</tt> related configuration options.
 * <p>
 * This filter will only execute once per request, to resolve servlet container
 * (specifically Weblogic) incompatibilities.
 * <p>
 * This filter MUST be executed BEFORE any authentication processing mechanisms.
 * Authentication processing mechanisms (e.g. BASIC, CAS processing filters etc) expect
 * the <code>SecurityContextHolder</code> to contain a valid <code>SecurityContext</code>
 * by the time they execute.
 * <p>
 * This is essentially a refactoring of the old
 * <tt>HttpSessionContextIntegrationFilter</tt> to delegate the storage issues to a
 * separate strategy, allowing for more customization in the way the security context is
 * maintained between requests.
 * <p>
 * The <tt>forceEagerSessionCreation</tt> property can be used to ensure that a session is
 * always available before the filter chain executes (the default is <code>false</code>,
 * as this is resource intensive and not recommended).
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class SecurityContextPersistenceFilter extends GenericFilterBean {

	/**
	 * 确保该Filter在一个request处理过程中最多被调到用一次的机制：
	 * 一旦该Fitler被调用过，他会在当前request增加该属性值为true，利用此标记
	 * 可以避免Filter被调用二次
	 */
	static final String FILTER_APPLIED = "__spring_security_scpf_applied";

	/**
	 * 安全上下文存储库
	 */
	private SecurityContextRepository repo;

	private boolean forceEagerSessionCreation = false;

	public SecurityContextPersistenceFilter() {
		// 缺省使用http session 作为安全上下文对象存储
		this(new HttpSessionSecurityContextRepository());
	}

	public SecurityContextPersistenceFilter(SecurityContextRepository repo) {
		this.repo = repo;
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		/**
		 * 检查调用标志，如果request上已经存在属性FILTER_APPLIED,
		 * 表明该Filter在该request的处理过程中已经被调用过
		 */
		if (request.getAttribute(FILTER_APPLIED) != null) {
			// ensure that filter is only applied once per request
			// 将请求转发给过滤器链上下一个filter
			chain.doFilter(request, response);
			return;
		}

		final boolean debug = logger.isDebugEnabled();

		// 设置该Filter已经被调用的标记
		request.setAttribute(FILTER_APPLIED, Boolean.TRUE);

		if (forceEagerSessionCreation) {
			HttpSession session = request.getSession();

			if (debug && session.isNew()) {
				logger.debug("Eagerly created session: " + session.getId());
			}
		}

		HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request,
				response);
		// 从安全上下文存储库(缺省是http session)中读取安全上下文对象
		SecurityContext contextBeforeChainExecution = repo.loadContext(holder);

		try {
			/**
			 * 设置安全上下文对象到SecurityContextHolder(这样应用中就可以通过SecurityContextHolder获取到安全上下文)然后才继续Filter chain的调用
 			 */
			SecurityContextHolder.setContext(contextBeforeChainExecution);

			chain.doFilter(holder.getRequest(), holder.getResponse());

		}
		finally {
			SecurityContext contextAfterChainExecution = SecurityContextHolder
					.getContext();
			// Crucial removal of SecurityContextHolder contents - do this before anything
			// else.
			// 当前请求已经被处理完成了，清除SecurityContextHolder并将最新的
			// 安全上下文对象保存回安全上下文存储库(缺省是http session)
			SecurityContextHolder.clearContext();
			// 重新将SecurityContext保存到HttpSession中
			repo.saveContext(contextAfterChainExecution, holder.getRequest(),
					holder.getResponse());
			request.removeAttribute(FILTER_APPLIED);

			if (debug) {
				logger.debug("SecurityContextHolder now cleared, as request processing completed");
			}
		}
	}

	public void setForceEagerSessionCreation(boolean forceEagerSessionCreation) {
		this.forceEagerSessionCreation = forceEagerSessionCreation;
	}
}
