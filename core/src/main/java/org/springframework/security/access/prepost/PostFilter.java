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
package org.springframework.security.access.prepost;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 	 @PostFilter： 在执行方法后过滤返回的集合或数组（筛选出当前用户具有 READ 权限的数据），returnObject 就表示方法的返回值。有一个和它对应的注解
 * 	 
 *   @PostFilter("hasPermission(filterObject, 'READ')")
 *   public List<NoticeMessage> findAll() {
 *         List<NoticeMessage> all = noticeMessageMapper.findAll();
 *         return all;
 *     }
 *
 *     
 * Annotation for specifying a method filtering expression which will be evaluated after a
 * method has been invoked.
 *
 * @author Luke Taylor
 * @since 3.0
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface PostFilter {
	/**
	 * @return the Spring-EL expression to be evaluated after invoking the protected
	 * method
	 */
	public String value();
}
