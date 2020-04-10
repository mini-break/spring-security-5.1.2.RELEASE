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
package org.springframework.security.web.context.request.async;

import java.io.IOException;
import java.util.concurrent.Callable;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.context.request.async.WebAsyncManager;
import org.springframework.web.context.request.async.WebAsyncUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 此过滤器用于集成SecurityContext到Spring异步执行机制中的WebAsyncManager
 * 
 * Provides integration between the {@link SecurityContext} and Spring Web's
 * {@link WebAsyncManager} by using the
 * {@link SecurityContextCallableProcessingInterceptor#beforeConcurrentHandling(org.springframework.web.context.request.NativeWebRequest, Callable)}
 * to populate the {@link SecurityContext} on the {@link Callable}.
 *
 * @author Rob Winch
 * @see SecurityContextCallableProcessingInterceptor
 */
public final class WebAsyncManagerIntegrationFilter extends OncePerRequestFilter {
	private static final Object CALLABLE_INTERCEPTOR_KEY = new Object();

	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		/**
		 * 从请求属性上获取所绑定的`WebAsyncManager`，如果尚未绑定，先做绑定
		 * 相应的属性名称为:org.springframework.web.context.request.async.WebAsyncManager.WEB_ASYNC_MANAGER
		 */
		WebAsyncManager asyncManager = WebAsyncUtils.getAsyncManager(request);

		/**
		 * 从 asyncManager 中获取 key 为 CALLABLE_INTERCEPTOR_KEY 的
		 * SecurityContextCallableProcessingInterceptor,  如果获取到的为 null，
		 * 说明其中还没有 key 为 CALLABLE_INTERCEPTOR_KEY 的
		 * SecurityContextCallableProcessingInterceptor, 新建一个并使用该 key注册上去
		 */
		SecurityContextCallableProcessingInterceptor securityProcessingInterceptor = (SecurityContextCallableProcessingInterceptor) asyncManager
				.getCallableInterceptor(CALLABLE_INTERCEPTOR_KEY);
		if (securityProcessingInterceptor == null) {
			/**
			 * 这里新建的 SecurityContextCallableProcessingInterceptor 实现了
			 * 接口 CallableProcessingInterceptor，当它被应用于一次异步执行时，
			 * 它的方法beforeConcurrentHandling() 会在调用者线程执行，
			 * 该方法会相应地从当前线程获取SecurityContext,然后被调用者线程中执行设计的逻辑时，
			 * 会使用这个SecurityContext，从而实现安全上下文从调用者线程到被调用者线程的传播
			 */
			asyncManager.registerCallableInterceptor(CALLABLE_INTERCEPTOR_KEY,
					new SecurityContextCallableProcessingInterceptor());
		}

		/**
		 * 上面是本过滤器的职责逻辑:为整个请求处理过程中可能的异步处理做安全上下文相关的准备。
		 * 现在该任务已经完成，继续 filter chain 的调用
		 */
		filterChain.doFilter(request, response);
	}
}
