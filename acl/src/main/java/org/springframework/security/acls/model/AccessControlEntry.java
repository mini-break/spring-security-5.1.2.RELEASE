/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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
package org.springframework.security.acls.model;

import java.io.Serializable;

/**
 * AccessControlEntry 简写为 ACE，一个 AccessControlEntry 对象代表一条权限记录。
 * 每一个 AccessControlEntry 都对应了一个 Acl，一个 Acl 对象对应多个 AccessControlEntry，有了这层对应关系，相当于就知道这个权限操作的是哪个对象。
 *
 * 然后 AccessControlEntry 中还包含一个 Sid 和一个 Permission 对象，表示某个 Sid 具备某种权限。
 *
 * 可以看到，Acl+ACE，就描述出来了某个 Sid 可以具备某个 ObjectIdentity 的某种 Permission
 * 
 * Represents an individual permission assignment within an {@link Acl}.
 *
 * <p>
 * Instances MUST be immutable, as they are returned by <code>Acl</code> and should not
 * allow client modification.
 * </p>
 *
 * @author Ben Alex
 *
 */
public interface AccessControlEntry extends Serializable {
	// ~ Methods
	// ========================================================================================================

	Acl getAcl();

	/**
	 * Obtains an identifier that represents this ACE.
	 *
	 * @return the identifier, or <code>null</code> if unsaved
	 */
	Serializable getId();

	Permission getPermission();

	Sid getSid();

	/**
	 * Indicates the permission is being granted to the relevant Sid. If false,
	 * indicates the permission is being revoked/blocked.
	 *
	 * @return true if being granted, false otherwise
	 */
	boolean isGranting();
}
