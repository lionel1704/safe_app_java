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
import net.maidsafe.safe_app.MDataEntry;
import net.maidsafe.safe_app.MDataValue;
import net.maidsafe.safe_app.NativeBindings;
import net.maidsafe.utils.Helper;

/**
 * Represent the entries of a mutable data network object.
 */
public class MDataEntries {
    private static AppHandle appHandle;

    public MDataEntries(final AppHandle appHandle) {
        init(appHandle);
    }

    private void init(final AppHandle handle) {
        this.appHandle = handle;
    }

    /**
     * Create a new empty Entries handle
     * @return New entries handle as {@link NativeHandle}
     */
    public CompletableFuture<NativeHandle> newEntriesHandle() {
        final CompletableFuture<NativeHandle> future = new CompletableFuture<>();
        NativeBindings.mdataEntriesNew(appHandle.toLong(), (result, entriesH) -> {
            if (result.getErrorCode() != 0) {
                future.completeExceptionally(Helper.ffiResultToException(result));
            }
            final NativeHandle entriesHandle = new NativeHandle(entriesH, handle -> {
                NativeBindings.mdataEntriesFree(appHandle.toLong(), handle, res -> {
                });
            });
            future.complete(entriesHandle);
        });
        return future;
    }

    /**
     * Insert an entry in the entry handle
     * @param entriesHandle The entries handle as {@link NativeHandle}
     * @param key Key of the MData entry
     * @param value Value of the MData entry
     */
    public CompletableFuture<Void> insert(final NativeHandle entriesHandle, final byte[] key, final byte[] value) {
        final CompletableFuture<Void> future = new CompletableFuture<Void>();
        NativeBindings.mdataEntriesInsert(appHandle.toLong(), entriesHandle.toLong(), key, value,
                result -> {
                    if (result.getErrorCode() != 0) {
                        future.completeExceptionally(Helper.ffiResultToException(result));
                    }
                    future.complete(null);
                });
        return future;
    }

    /**
     * Returns the number of entries in the mutable data
     * @param entriesHandle The entries handle as {@link NativeHandle}
     * @return Number of entries in the mutable data
     */
    public CompletableFuture<Long> length(final NativeHandle entriesHandle) {
        final CompletableFuture<Long> future = new CompletableFuture<>();
        NativeBindings.mdataEntriesLen(appHandle.toLong(), entriesHandle.toLong(), (result, len) -> {
            if (result.getErrorCode() != 0) {
                future.completeExceptionally(Helper.ffiResultToException(result));
            }
            future.complete(len);
        });
        return future;
    }

    /**
     * Get the value for the given key in the mutable data
     * @param entriesHandle Entries handle as {@link NativeHandle}
     * @param key The key of the MDataEntry
     * @return The MDataValue of the given key
     */
    public CompletableFuture<MDataValue> getValue(final NativeHandle entriesHandle, final byte[] key) {
        final CompletableFuture<MDataValue> future = new CompletableFuture<>();
        NativeBindings.mdataEntriesGet(appHandle.toLong(), entriesHandle.toLong(), key,
                (result, value, version) -> {
                    if (result.getErrorCode() != 0) {
                        future.completeExceptionally(Helper.ffiResultToException(result));
                    }
                    final MDataValue mDataValue = new MDataValue();
                    mDataValue.setContent(value);
                    mDataValue.setContentLen(value.length);
                    mDataValue.setEntryVersion(version);
                    future.complete(mDataValue);
                });
        return future;
    }

    /**
     * List the entries in the Mutable data
     * @param entriesHandle The entries handle as {@link NativeHandle}
     * @return List of entries in the mutable data List&lt;{@link MDataEntry}&gt;
     */
    public CompletableFuture<List<MDataEntry>> listEntries(final NativeHandle entriesHandle) {
        final CompletableFuture<List<MDataEntry>> future = new CompletableFuture<>();
        NativeBindings.mdataListEntries(appHandle.toLong(), entriesHandle.toLong(),
                (result, entries) -> {
                    if (result.getErrorCode() != 0) {
                        future.completeExceptionally(Helper.ffiResultToException(result));
                    }
                    future.complete(Arrays.asList(entries));
                });
        return future;
    }
}
