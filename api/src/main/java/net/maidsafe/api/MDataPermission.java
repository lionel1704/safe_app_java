// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.
package net.maidsafe.api;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import net.maidsafe.api.model.NativeHandle;
import net.maidsafe.safe_app.NativeBindings;
import net.maidsafe.safe_app.PermissionSet;
import net.maidsafe.safe_app.UserPermissionSet;
import net.maidsafe.utils.Helper;

/**
 * Exposes the permission APIs for mutable data
 */
public class MDataPermission {

    private AppHandle appHandle;

    public MDataPermission(final AppHandle appHandle) {
        init(appHandle);
    }

    private void init(final AppHandle handle) {
        this.appHandle = handle;
    }

    /**
     * Create a new handle for mutable data permissions
     * @return A new permission handle as {@link NativeHandle}
     */
    public CompletableFuture<NativeHandle> newPermissionHandle() {
        final CompletableFuture<NativeHandle> future = new CompletableFuture<>();
        NativeBindings.mdataPermissionsNew(appHandle.toLong(), (result, permissionsHandle) -> {
            if (result.getErrorCode() != 0) {
                future.completeExceptionally(Helper.ffiResultToException(result));
            }
            future.complete(new NativeHandle(permissionsHandle, handle -> {
                NativeBindings.mdataPermissionsFree(appHandle.toLong(), handle, res -> {
                });
            }));
        });
        return future;
    }

    /**
     * Get the number of permissions included in the mutable data
     * @param permissionHandle Permissions handle as {@link NativeHandle}
     * @return Number of permissions in the mutable data
     */
    public CompletableFuture<Long> getLength(final NativeHandle permissionHandle) {
        final CompletableFuture<Long> future = new CompletableFuture<>();
        NativeBindings.mdataPermissionsLen(appHandle.toLong(), permissionHandle.toLong(),
                (result, len) -> {
                    if (result.getErrorCode() != 0) {
                        future.completeExceptionally(Helper.ffiResultToException(result));
                    }
                    future.complete(len);
                });
        return future;
    }

    /**
     * Returns the permission set for a particular user
     * @param permissionHandle Permission handle as {@link NativeHandle}
     * @param signKey Public sign key of the user
     * @return Set of permissions as {@link PermissionSet}
     */
    public CompletableFuture<PermissionSet> getPermissionForUser(final NativeHandle permissionHandle,
                                                                 final NativeHandle signKey) {
        final CompletableFuture<PermissionSet> future = new CompletableFuture<>();
        NativeBindings.mdataPermissionsGet(appHandle.toLong(), permissionHandle.toLong(),
                signKey.toLong(), (result, permsSet) -> {
                    if (result.getErrorCode() != 0) {
                        future.completeExceptionally(Helper.ffiResultToException(result));
                    }
                    future.complete(permsSet);
                });
        return future;
    }

    /**
     * List all the associated permission sets
     * @param permissionHandle Permission handle as {@link NativeHandle}
     * @return List of {@link UserPermissionSet}
     */
    public CompletableFuture<List<UserPermissionSet>> listAll(final NativeHandle permissionHandle) {
        final CompletableFuture<List<UserPermissionSet>> future = new CompletableFuture<>();
        NativeBindings.mdataListPermissionSets(appHandle.toLong(), permissionHandle.toLong(),
                (result, permsArray) -> {
                    if (result.getErrorCode() != 0) {
                        future.completeExceptionally(Helper.ffiResultToException(result));
                    }
                    future.complete(Arrays.asList(permsArray));
                });
        return future;
    }

    /**
     * Insert a new permission set
     * @param permissionHandle Permission handle as {@link NativeHandle}
     * @param publicSignKey Public sign key for the user. To insert for anyone pass Constants.ZERO_HANDLE
     * @param permissionSet Set of permissions to be assigned
     */
    public CompletableFuture insert(final NativeHandle permissionHandle, final NativeHandle publicSignKey,
                                    final PermissionSet permissionSet) {
        final CompletableFuture<Void> future = new CompletableFuture<Void>();
        NativeBindings.mdataPermissionsInsert(appHandle.toLong(), permissionHandle.toLong(),
                publicSignKey.toLong(), permissionSet, (result) -> {
                    if (result.getErrorCode() != 0) {
                        future.completeExceptionally(Helper.ffiResultToException(result));
                    }
                    future.complete(null);
                });
        return future;
    }
}
