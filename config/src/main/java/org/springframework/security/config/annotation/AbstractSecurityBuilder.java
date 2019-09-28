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
package org.springframework.security.config.annotation;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 该抽象基类约定了使用此类构建器对象构建目标对象时,目标对象被构建最多一次(实际作用可以看出来就是返回一个 O 类型的`单例`对象)。
 * 该行为是通过使用一个AtomicBoolean building标志位来控制的。
 * 只有在该标志为false时,调用构建器的#build方法才会触发执行目标对象的构建逻辑。
 * 如果该标志为true时调用构建器的#build方法,则会出现异常AlreadyBuiltException("This object has already been built")
 *
 * A base {@link SecurityBuilder} that ensures the object being built is only built one
 * time.
 *
 * @param <O> the type of Object that is being built
 *
 * @author Rob Winch
 *
 */
public abstract class AbstractSecurityBuilder<O> implements SecurityBuilder<O> {
	/**
	 * 原子变量,相当于值为false的原子变量
	 * AtomicBoolean building = new AtomicBoolean(false)
	 */
	private AtomicBoolean building = new AtomicBoolean();

	private O object;

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.security.config.annotation.SecurityBuilder#build()
	 */
	@Override
	public final O build() throws Exception {
		// AtomicBoolean值为false时执行，同时更新AtomicBoolean值为true
		if (this.building.compareAndSet(false, true)) {
			this.object = doBuild();
			return this.object;
		}
		throw new AlreadyBuiltException("This object has already been built");
	}

	/**
	 * Gets the object that was built. If it has not been built yet an Exception is
	 * thrown.
	 *
	 * @return the Object that was built
	 */
	public final O getObject() {
		if (!this.building.get()) {
			throw new IllegalStateException("This object has not been built");
		}
		return this.object;
	}

	/**
	 * 类继承实现 doBuild(), 做实际的 Build 逻辑
	 * 
	 * Subclasses should implement this to perform the build.
	 *
	 * @return the object that should be returned by {@link #build()}.
	 *
	 * @throws Exception if an error occurs
	 */
	protected abstract O doBuild() throws Exception;
}
