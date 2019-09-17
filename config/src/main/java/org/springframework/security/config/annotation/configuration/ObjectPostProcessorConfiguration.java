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
package org.springframework.security.config.annotation.configuration;

import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

/**
 * ObjectPostProcessorConfiguration 配置用于创建 AutowireBeanFactoryObjectPostProcessor 类
 * AutowireBeanFactoryObjectPostProcessor 的作用
 * Spring Security 的配置机制会使用到很多对象, 比如 WebSecurity, ProviderManager, 各个安全Filter等。
 * 但对象的创建并不是通过bean定义的形式被容器发现和注册进入容器的。而是 new 的.
 * 但对于这些并未被容器管理的对象, Spring Security 也希望它们成为一个被容器管理的 bean
 * 注入相应的依赖, 执行 applyBeanPostProcessorsAfterInitialization() 可以 afterSingletonsInstantiated, destroy
 * 为达成这个目标，Spring Security配置机制提供了一个工具类AutowireBeanFactoryObjectPostProcessor
 * 
 * Spring {@link Configuration} that exports the default {@link ObjectPostProcessor}. This
 * class is not intended to be imported manually rather it is imported automatically when
 * using {@link EnableWebSecurity} or {@link EnableGlobalMethodSecurity}.
 *
 * @see EnableWebSecurity
 * @see EnableGlobalMethodSecurity
 *
 * @author Rob Winch
 * @since 3.2
 */
@Configuration
public class ObjectPostProcessorConfiguration {

	@Bean
	public ObjectPostProcessor<Object> objectPostProcessor(
			AutowireCapableBeanFactory beanFactory) {
		return new AutowireBeanFactoryObjectPostProcessor(beanFactory);
	}

	// 例子
	// objectObjectPostProcessor.postProcess(new DemoClass());
	// 等于把 new DemoClass() 注入到了 IOC 容器
}
