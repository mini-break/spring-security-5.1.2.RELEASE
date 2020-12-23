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
package org.springframework.security.web;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;
import java.util.*;

/**
 * SecurityFilterChain 其实就是我们平时所说的 Spring Security 中的过滤器链
 * 
 * 通过build()获取到实例后，存入FilterChainProxy的属性List<SecurityFilterChain> filterChains中,
 * FilterChainProxy.doFilterInternal()中执行getFilters(HttpServletRequest request)
 * 找出对应request的SecurityFilterChain并返回Filters
 *
 * Defines a filter chain which is capable of being matched against an
 * {@code HttpServletRequest}. in order to decide whether it applies to that request.
 * <p>
 * Used to configure a {@code FilterChainProxy}.
 *
 *
 * @author Luke Taylor
 *
 * @since 3.1
 */
public interface SecurityFilterChain {

	/**
	 * 请求能否被匹配
	 */
	boolean matches(HttpServletRequest request);

	/**
	 * 返回此过滤器链的全部过滤器
	 */
	List<Filter> getFilters();
}
