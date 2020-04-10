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
package org.springframework.security.web.header.writers;

/**
 * 互联网上的资源有各种类型，通常浏览器会根据响应头的Content-Type字段来分辨它们的类型。
 * 例如："text/html"代表html文档，"image/png"是PNG图片，"text/css"是CSS样式文档。
 * 然而，有些资源的Content-Type是错的或者未定义。这时，某些浏览器会启用MIME-sniffing来猜测该资源的类型，解析内容并执行。
 * 例如，我们即使给一个html文档指定Content-Type为"text/plain"，在IE8-中这个文档依然会被当做html来解析。
 * 利用浏览器的这个特性，攻击者甚至可以让原本应该解析为图片的请求被解析为JavaScript。通过下面这个响应头可以禁用浏览器的类型猜测行为：
 * X-Content-Type-Options: nosniff
 *
 * A {@link StaticHeadersWriter} that inserts headers to prevent content sniffing.
 * Specifically the following headers are set:
 * <ul>
 * <li>X-Content-Type-Options: nosniff</li>
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class XContentTypeOptionsHeaderWriter extends StaticHeadersWriter {

	/**
	 * Creates a new instance
	 */
	public XContentTypeOptionsHeaderWriter() {
		super("X-Content-Type-Options", "nosniff");
	}
}
