/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.web.csrf;

import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.util.Assert;

/**
 * 一个基于HttpSession保存csrf token的存储库实现
 * 
 * A {@link CsrfTokenRepository} that stores the {@link CsrfToken} in the
 * {@link HttpSession}.
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class HttpSessionCsrfTokenRepository implements CsrfTokenRepository {
	private static final String DEFAULT_CSRF_PARAMETER_NAME = "_csrf";

	private static final String DEFAULT_CSRF_HEADER_NAME = "X-CSRF-TOKEN";

	private static final String DEFAULT_CSRF_TOKEN_ATTR_NAME = HttpSessionCsrfTokenRepository.class
			.getName().concat(".CSRF_TOKEN");

	/**
	 * 将 csrf token 保存在请求参数中时，使用的参数名称
	 */
	private String parameterName = DEFAULT_CSRF_PARAMETER_NAME;

	/**
	 * 将 csrf token 保存在HTTP头部时，使用的头部名称
	 */
	private String headerName = DEFAULT_CSRF_HEADER_NAME;

	/**
	 * 将 csrf token 保存在 http session 中时使用的属性名称
	 */
	private String sessionAttributeName = DEFAULT_CSRF_TOKEN_ATTR_NAME;

	/*
	 * 保存 csrf token 到当前请求对应的 http session 中
	 */
	public void saveToken(CsrfToken token, HttpServletRequest request,
			HttpServletResponse response) {
		if (token == null) {
			/**
			 * 如果将要保存的 csrf token 为 null，则获取当前 session，清除其中的csrf token 属性
			 */
			HttpSession session = request.getSession(false);
			if (session != null) {
				session.removeAttribute(this.sessionAttributeName);
			}
		}
		else {
			/**
			 * 如果将要保存的 csrf token 不为 null， 则获取将当前 session，将csrf token 保存到其中
			 */
			HttpSession session = request.getSession();
			session.setAttribute(this.sessionAttributeName, token);
		}
	}

	/*
	 * 从当前 http session 中获取所保存的 csrf token
	 */
	public CsrfToken loadToken(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		if (session == null) {
			return null;
		}
		return (CsrfToken) session.getAttribute(this.sessionAttributeName);
	}

	/*
	 * 针对当前请求生成一个 csrf token 对象 CsrfToken， 实现类使用 DefaultCsrfToken,
     * 这里设置了该 CsrfToken 在头部中保存时的名称为 this.headerName, 在参数中保存时
	 * 的名称为 this.parameterName,csrf token 的值为一个随机 UUID 的字符串值
	 */
	public CsrfToken generateToken(HttpServletRequest request) {
		return new DefaultCsrfToken(this.headerName, this.parameterName,
				createNewToken());
	}

	/**
	 * Sets the {@link HttpServletRequest} parameter name that the {@link CsrfToken} is
	 * expected to appear on
	 * @param parameterName the new parameter name to use
	 */
	public void setParameterName(String parameterName) {
		Assert.hasLength(parameterName, "parameterName cannot be null or empty");
		this.parameterName = parameterName;
	}

	/**
	 * Sets the header name that the {@link CsrfToken} is expected to appear on and the
	 * header that the response will contain the {@link CsrfToken}.
	 *
	 * @param headerName the new header name to use
	 */
	public void setHeaderName(String headerName) {
		Assert.hasLength(headerName, "headerName cannot be null or empty");
		this.headerName = headerName;
	}

	/**
	 * Sets the {@link HttpSession} attribute name that the {@link CsrfToken} is stored in
	 * @param sessionAttributeName the new attribute name to use
	 */
	public void setSessionAttributeName(String sessionAttributeName) {
		Assert.hasLength(sessionAttributeName,
				"sessionAttributename cannot be null or empty");
		this.sessionAttributeName = sessionAttributeName;
	}

	/**
	 * 产生一个 csrf token 的值，其实是一个随机 UUID 的字符串形式
	 */
	private String createNewToken() {
		return UUID.randomUUID().toString();
	}
}
