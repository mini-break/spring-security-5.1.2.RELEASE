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
package org.springframework.security.web.header.writers;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.header.HeaderWriter;
import org.springframework.util.Assert;

/**
 * 什么是referrer?
 * 当一个用户点击当前页面中的一个链接，然后跳转到目标页面时，目标页面会收到一个信息，即用户是从哪个源链接跳转过来的。
 * 也就是说，当你发起一个http请求，请求头中的referrer字段就说明了你是从哪个页面发起该请求的。
 *
 * 使用场景
 * 有时候我们需要控制这个referrer字段的值，即是否让其显示在请求头中，或者是否显示完整路径等。尤其是在以下两个使用场景：
 * 隐私
 * 在社交网站的个人中心页面，也许会存在一些外链，这时候社交网站肯定不希望用户在点击这些链接跳转到其他第三方网站时会将自己个人中心
 * 的URL信息显示在referrer字段中传过去，尤其是个人中心页面的URL往往会带着用户数据和一些敏感信息。
 * 这时候可以选择不显示来源页面URL信息或者只显示一个网站根地址hostname。
 * 安全
 * 有些使用了https的网站，可能在URL中使用一个参数（sid）来作为用户身份凭证，而又需要引入其他https网站的资源，这种情况，
 * 网站肯定不希望泄露用户的身份凭证信息。当https网站需要引入不安全的http网站的资源或者有链接要跳转到http网站时，
 * 这时候将https源网站的URL信息传过去也是不太安全的。
 *
 * <p>
 * Provides support for <a href="https://www.w3.org/TR/referrer-policy/">Referrer Policy</a>.
 * </p>
 *
 * <p>
 * The list of policies defined can be found at
 * <a href="https://www.w3.org/TR/referrer-policy/#referrer-policies">Referrer Policies</a>.
 * </p>
 *
 * <p>
 * This implementation of {@link HeaderWriter} writes the following header:
 * </p>
 * <ul>
 *  <li>Referrer-Policy</li>
 * </ul>
 *
 * <p>
 * By default, the Referrer-Policy header is not included in the response.
 * Policy <b>no-referrer</b> is used by default if no {@link ReferrerPolicy} is set.
 * </p>
 *
 * @author Eddú Meléndez
 * @author Kazuki Shimizu
 * @since 4.2
 */
public class ReferrerPolicyHeaderWriter implements HeaderWriter {

	private static final String REFERRER_POLICY_HEADER = "Referrer-Policy";

	private ReferrerPolicy policy;

	/**
	 * Creates a new instance. Default value: no-referrer.
	 */
	public ReferrerPolicyHeaderWriter() {
		this(ReferrerPolicy.NO_REFERRER);
	}

	/**
	 * Creates a new instance.
	 *
	 * @param policy a referrer policy
	 * @throws IllegalArgumentException if policy is null
	 */
	public ReferrerPolicyHeaderWriter(ReferrerPolicy policy) {
		setPolicy(policy);
	}

	/**
	 * Sets the policy to be used in the response header.
	 * @param policy a referrer policy
	 * @throws IllegalArgumentException if policy is null
	 */
	public void setPolicy(ReferrerPolicy policy) {
		Assert.notNull(policy, "policy can not be null");
		this.policy = policy;
	}

	/**
	 * @see org.springframework.security.web.header.HeaderWriter#writeHeaders(HttpServletRequest, HttpServletResponse)
	 */
	@Override
	public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
		response.setHeader(REFERRER_POLICY_HEADER, this.policy.getPolicy());
	}

	public enum ReferrerPolicy {

		NO_REFERRER("no-referrer"),
		NO_REFERRER_WHEN_DOWNGRADE("no-referrer-when-downgrade"),
		SAME_ORIGIN("same-origin"),
		ORIGIN("origin"),
		STRICT_ORIGIN("strict-origin"),
		ORIGIN_WHEN_CROSS_ORIGIN("origin-when-cross-origin"),
		STRICT_ORIGIN_WHEN_CROSS_ORIGIN("strict-origin-when-cross-origin"),
		UNSAFE_URL("unsafe-url");

		private static final Map<String, ReferrerPolicy> REFERRER_POLICIES;

		static {
			Map<String, ReferrerPolicy> referrerPolicies = new HashMap<>();
			for (ReferrerPolicy referrerPolicy : values()) {
				referrerPolicies.put(referrerPolicy.getPolicy(), referrerPolicy);
			}
			REFERRER_POLICIES = Collections.unmodifiableMap(referrerPolicies);
		}

		private String policy;

		ReferrerPolicy(String policy) {
			this.policy = policy;
		}

		public String getPolicy() {
			return this.policy;
		}

		public static ReferrerPolicy get(String referrerPolicy) {
			return REFERRER_POLICIES.get(referrerPolicy);
		}
	}

}
