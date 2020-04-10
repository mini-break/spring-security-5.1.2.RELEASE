/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.web.header.writers.frameoptions;

import org.springframework.security.web.header.HeaderWriter;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * X-Frame-Options 响应头有三个可选的值：
 * DENY：页面不能被嵌入到任何iframe或frame中
 * SAMEORIGIN：页面只能被本站页面嵌入到iframe或者frame中
 * ALLOW-FROM：页面允许frame或frame加载
 * 
 * {@code HeaderWriter} implementation for the X-Frame-Options headers. When using the
 * ALLOW-FROM directive the actual value is determined by a {@code AllowFromStrategy}.
 *
 * @author Marten Deinum
 * @author Rob Winch
 * @since 3.2
 *
 * @see AllowFromStrategy
 */
public final class XFrameOptionsHeaderWriter implements HeaderWriter {

	public static final String XFRAME_OPTIONS_HEADER = "X-Frame-Options";

	private final AllowFromStrategy allowFromStrategy;
	private final XFrameOptionsMode frameOptionsMode;

	/**
	 * Creates an instance with {@link XFrameOptionsMode#DENY}
	 */
	public XFrameOptionsHeaderWriter() {
		this(XFrameOptionsMode.DENY);
	}

	/**
	 * Creates a new instance
	 *
	 * @param frameOptionsMode the {@link XFrameOptionsMode} to use. If using
	 * {@link XFrameOptionsMode#ALLOW_FROM}, use
	 * {@link #XFrameOptionsHeaderWriter(AllowFromStrategy)} instead.
	 */
	public XFrameOptionsHeaderWriter(XFrameOptionsMode frameOptionsMode) {
		Assert.notNull(frameOptionsMode, "frameOptionsMode cannot be null");
		if (XFrameOptionsMode.ALLOW_FROM.equals(frameOptionsMode)) {
			throw new IllegalArgumentException(
					"ALLOW_FROM requires an AllowFromStrategy. Please use FrameOptionsHeaderWriter(AllowFromStrategy allowFromStrategy) instead");
		}
		this.frameOptionsMode = frameOptionsMode;
		this.allowFromStrategy = null;
	}

	/**
	 * Creates a new instance with {@link XFrameOptionsMode#ALLOW_FROM}.
	 *
	 * @param allowFromStrategy the strategy for determining what the value for ALLOW_FROM
	 * is.
	 */
	public XFrameOptionsHeaderWriter(AllowFromStrategy allowFromStrategy) {
		Assert.notNull(allowFromStrategy, "allowFromStrategy cannot be null");
		this.frameOptionsMode = XFrameOptionsMode.ALLOW_FROM;
		this.allowFromStrategy = allowFromStrategy;
	}

	/**
	 * Writes the X-Frame-Options header value, overwritting any previous value.
	 *
	 * @param request the servlet request
	 * @param response the servlet response
	 */
	public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
		if (XFrameOptionsMode.ALLOW_FROM.equals(frameOptionsMode)) {
			String allowFromValue = this.allowFromStrategy.getAllowFromValue(request);
			if (XFrameOptionsMode.DENY.getMode().equals(allowFromValue)) {
				response.setHeader(XFRAME_OPTIONS_HEADER, XFrameOptionsMode.DENY.getMode());
			} else if (allowFromValue != null) {
				response.setHeader(XFRAME_OPTIONS_HEADER,
						XFrameOptionsMode.ALLOW_FROM.getMode() + " " + allowFromValue);
			}
		}
		else {
			response.setHeader(XFRAME_OPTIONS_HEADER, frameOptionsMode.getMode());
		}
	}

	/**
	 * The possible values for the X-Frame-Options header.
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	public enum XFrameOptionsMode {
		DENY("DENY"), SAMEORIGIN("SAMEORIGIN"), ALLOW_FROM("ALLOW-FROM");

		private String mode;

		private XFrameOptionsMode(String mode) {
			this.mode = mode;
		}

		/**
		 * Gets the mode for the X-Frame-Options header value. For example, DENY,
		 * SAMEORIGIN, ALLOW-FROM. Cannot be null.
		 *
		 * @return the mode for the X-Frame-Options header value.
		 */
		private String getMode() {
			return mode;
		}
	}
}
