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
import net.maidsafe.safe_app.MDataInfo;
import net.maidsafe.safe_app.MDataKey;
import net.maidsafe.safe_app.MDataValue;
import net.maidsafe.safe_app.MetadataResponse;
import net.maidsafe.safe_app.NativeBindings;
import net.maidsafe.safe_app.PermissionSet;
import net.maidsafe.utils.Helper;

/**
 * Exposes API for Mutable Data operations
 */
public final class MData {
    private static AppHandle appHandle;

    public MData(final AppHandle appHandle) {
        init(appHandle);
    }

    private void init(final AppHandle handle) {
        this.appHandle = handle;
    }

    /**
     * Create a new Mutable data with the defined name and type tag
     * @param name Name(address) of the mutable data
     * @param typeTag Mutable data type tag
     * @param secretKey Secret key of the MData owner
     * @param nonce A unique nonce
     * @return Mutable data info as {@link MDataInfo}
     */
    public CompletableFuture<MDataInfo> getPrivateMData(final byte[] name, final long typeTag, final byte[] secretKey,
                                                        final byte[] nonce) {
        final CompletableFuture<MDataInfo> future = new CompletableFuture<>();
        NativeBindings.mdataInfoNewPrivate(name, typeTag, secretKey, nonce, (result, mdInfo) -> {
            if (result.getErrorCode() != 0) {
                future.completeExceptionally(Helper.ffiResultToException(result));
            }
            future.complete(mdInfo);
        });
        return future;
    }

    /**
     * Generate private mutable data at a random address
     * @param typeTag MData type tag
     * @return Mutable data info as {@link MDataInfo}
     */
    public CompletableFuture<MDataInfo> getRandomPrivateMData(final long typeTag) {
        final CompletableFuture<MDataInfo> future = new CompletableFuture<>();
        NativeBindings.mdataInfoRandomPrivate(typeTag, (result, mdInfo) -> {
            if (result.getErrorCode() != 0) {
                future.completeExceptionally(Helper.ffiResultToException(result));
            }
            future.complete(mdInfo);
        });
        return future;
    }

    /**
     * Generate public mutable data at a random address
     * @param typeTag MData type tag
     * @return Mutable data info as {@link MDataInfo}
     */
    public CompletableFuture<MDataInfo> getRandomPublicMData(final long typeTag) {
        final CompletableFuture<MDataInfo> future = new CompletableFuture<>();
        NativeBindings.mdataInfoRandomPublic(typeTag, (result, mdInfo) -> {
            if (result.getErrorCode() != 0) {
                future.completeExceptionally(Helper.ffiResultToException(result));
            }
            future.complete(mdInfo);
        });
        return future;
    }

    /**
     * Encrypt the key of an MData entry
     * @param mDataInfo Mutable data info as {@link MDataInfo}
     * @param key Key to be encrypted as byte array
     * @return Encrypted key as byte array
     */
    public CompletableFuture<byte[]> encryptEntryKey(final MDataInfo mDataInfo, final byte[] key) {
        final CompletableFuture<byte[]> future = new CompletableFuture<>();
        NativeBindings.mdataInfoEncryptEntryKey(mDataInfo, key, (result, encryptedKey) -> {
            if (result.getErrorCode() != 0) {
                future.completeExceptionally(Helper.ffiResultToException(result));
            }
            future.complete(encryptedKey);
        });
        return future;
    }

    /**
     * Encrypt the value of an MData entry
     * @param mDataInfo Mutable data info as {@link MDataInfo}
     * @param value Value to be encrypted as byte array
     * @return Encrypted value as byte array
     */
    public CompletableFuture<byte[]> encryptEntryValue(final MDataInfo mDataInfo, final byte[] value) {
        final CompletableFuture<byte[]> future = new CompletableFuture<>();
        NativeBindings.mdataInfoEncryptEntryValue(mDataInfo, value, (result, encryptedValue) -> {
            if (result.getErrorCode() != 0) {
                future.completeExceptionally(Helper.ffiResultToException(result));
            }
            future.complete(encryptedValue);
        });
        return future;
    }

    /**
     * Decrypt an MData entry's key/value
     * @param mDataInfo Mutable data info as {@link MDataInfo}
     * @param value Encrypted key/value
     * @return Decrypted key/value as byte array
     */
    public CompletableFuture<byte[]> decrypt(final MDataInfo mDataInfo, final byte[] value) {
        final CompletableFuture<byte[]> future = new CompletableFuture<>();
        NativeBindings.mdataInfoDecrypt(mDataInfo, value, (result, decryptedValue) -> {
            if (result.getErrorCode() != 0) {
                future.completeExceptionally(Helper.ffiResultToException(result));
            }
            future.complete(decryptedValue);
        });
        return future;
    }

    /**
     * Serialize the Mutable data info as a byte array
     * @param mDataInfo Mutable data info as {@link MDataInfo}
     * @return Serialized mDataInfo as byte array
     */
    public CompletableFuture<byte[]> serialise(final MDataInfo mDataInfo) {
        final CompletableFuture<byte[]> future = new CompletableFuture<>();
        NativeBindings.mdataInfoSerialise(mDataInfo, (result, serialisedData) -> {
            if (result.getErrorCode() != 0) {
                future.completeExceptionally(Helper.ffiResultToException(result));
            }
            future.complete(serialisedData);
        });
        return future;
    }

    /**
     * Deserialize mutable data info
     * @param serialisedMData Serialized mDataInfo
     * @return Deserialized mDataInfo as {@link MDataInfo}
     */
    public CompletableFuture<MDataInfo> deserialise(final byte[] serialisedMData) {
        final CompletableFuture<MDataInfo> future = new CompletableFuture<>();
        NativeBindings.mdataInfoDeserialise(serialisedMData, (result, mDataInfo) -> {
            if (result.getErrorCode() != 0) {
                future.completeExceptionally(Helper.ffiResultToException(result));
            }
            future.complete(mDataInfo);
        });
        return future;
    }

    /**
     * Put the Mutable data onto the network
     * @param mDataInfo Mutable data info as {@link MDataInfo}
     * @param permissionHandle Permission handle as {@link NativeHandle}
     * @param entriesHandle Entries handle as {@link NativeHandle}
     */
    public CompletableFuture<Void> put(final MDataInfo mDataInfo, final NativeHandle permissionHandle,
                                       final NativeHandle entriesHandle) {
        final CompletableFuture<Void> future = new CompletableFuture<Void>();
        NativeBindings.mdataPut(appHandle.toLong(), mDataInfo, permissionHandle.toLong(),
                entriesHandle.toLong(), (result) -> {
                    if (result.getErrorCode() != 0) {
                        future.completeExceptionally(Helper.ffiResultToException(result));
                    }
                    future.complete(null);
                });
        return future;
    }

    /**
     * Return the version of the mutable data shell
     * @param mDataInfo Mutable data info as {@link MDataInfo}
     * @return Version of the MData shell
     */
    public CompletableFuture<Long> getVersion(final MDataInfo mDataInfo) {
        final CompletableFuture<Long> future = new CompletableFuture<>();
        NativeBindings.mdataGetVersion(appHandle.toLong(), mDataInfo, (result, version) -> {
            if (result.getErrorCode() != 0) {
                future.completeExceptionally(Helper.ffiResultToException(result));
            }
            future.complete(version);
        });
        return future;
    }

    /**
     * Return the size of the serialized mutable data info
     * @param mDataInfo Mutable data info as {@link MDataInfo}
     * @return Serialized size of the mDataInfo
     */
    public CompletableFuture<Long> getSerialisedSize(final MDataInfo mDataInfo) {
        final CompletableFuture<Long> future = new CompletableFuture<>();
        NativeBindings.mdataSerialisedSize(appHandle.toLong(), mDataInfo, (result, size) -> {
            if (result.getErrorCode() != 0) {
                future.completeExceptionally(Helper.ffiResultToException(result));
            }
            future.complete(size);
        });
        return future;
    }

    /**
     * Return the value for the entry with the given key
     * @param mDataInfo Mutable data info as {@link MDataInfo}
     * @param key Key of the mutable data entry
     * @return Value of the mutable data as {@link MDataValue}
     */
    public CompletableFuture<MDataValue> getValue(final MDataInfo mDataInfo, final byte[] key) {
        final CompletableFuture<MDataValue> future = new CompletableFuture<>();
        NativeBindings.mdataGetValue(appHandle.toLong(), mDataInfo, key,
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
     * Get the handle for the entries in the Mutable data
     * @param mDataInfo Mutable data info as {@link MDataInfo}
     * @return Entries handle as {@link NativeHandle}
     */
    public CompletableFuture<NativeHandle> getEntriesHandle(final MDataInfo mDataInfo) {
        final CompletableFuture<NativeHandle> future = new CompletableFuture<>();
        NativeBindings.mdataEntries(appHandle.toLong(), mDataInfo, (result, entriesH) -> {
            if (result.getErrorCode() != 0) {
                future.completeExceptionally(Helper.ffiResultToException(result));
            }

            future.complete(new NativeHandle(entriesH,
                    (h) -> NativeBindings.mdataEntriesFree(appHandle.toLong(), entriesH, (r) -> {
                    })));
        });
        return future;
    }

    /**
     * Retrieve the list of keys in the Mutable data entries
     * @param mDataInfo Mutable data info as {@link MDataInfo}
     * @return List of keys in the mutable data as List&lt;{@link MDataKey}&gt;
     */
    public CompletableFuture<List<MDataKey>> getKeys(final MDataInfo mDataInfo) {
        final CompletableFuture<List<MDataKey>> future = new CompletableFuture<>();
        NativeBindings.mdataListKeys(appHandle.toLong(), mDataInfo, (result, keys) -> {
            if (result.getErrorCode() != 0) {
                future.completeExceptionally(Helper.ffiResultToException(result));
            }
            future.complete(Arrays.asList(keys));
        });
        return future;
    }

    /**
     * Retrieve the list of values in the Mutable data entries
     * @param mDataInfo Mutable data info as {@link MDataInfo}
     * @return List of values in the mutable data as List&lt;{@link MDataValue}&gt;
     */
    public CompletableFuture<List<MDataValue>> getValues(final MDataInfo mDataInfo) {
        final CompletableFuture<List<MDataValue>> future = new CompletableFuture<>();
        NativeBindings.mdataListValues(appHandle.toLong(), mDataInfo, (result, values) -> {
            if (result.getErrorCode() != 0) {
                future.completeExceptionally(Helper.ffiResultToException(result));
            }
            future.complete(Arrays.asList(values));
        });
        return future;
    }

    /**
     * Mutate the existing mutable data on the network
     * @param mDataInfo Mutable data info as {@link MDataInfo}
     * @param actionHandle Action handle that contains the MData operations
     */
    public CompletableFuture<Void> mutateEntries(final MDataInfo mDataInfo, final NativeHandle actionHandle) {
        final CompletableFuture<Void> future = new CompletableFuture<Void>();
        NativeBindings.mdataMutateEntries(appHandle.toLong(), mDataInfo, actionHandle.toLong(),
                (result) -> {
                    if (result.getErrorCode() != 0) {
                        future.completeExceptionally(Helper.ffiResultToException(result));
                    }
                    future.complete(null);
                });
        return future;
    }

    /**
     * Get the permission handle for the mutable data
     * @param mDataInfo Mutable data info as {@link MDataInfo}
     * @return Permission handle as {@link NativeHandle}
     */
    public CompletableFuture<NativeHandle> getPermission(final MDataInfo mDataInfo) {
        final CompletableFuture<NativeHandle> future = new CompletableFuture<>();
        NativeBindings.mdataListPermissions(appHandle.toLong(), mDataInfo, (result, permsHandle) -> {
            if (result.getErrorCode() != 0) {
                future.completeExceptionally(Helper.ffiResultToException(result));
            }
            final NativeHandle permissionHandle = new NativeHandle(permsHandle, (handle) -> {
                NativeBindings.mdataPermissionsFree(appHandle.toLong(), handle, res -> {
                });
            });
            future.complete(permissionHandle);
        });
        return future;
    }

    /**
     * Get the permissions given to a user
     * @param publicSignKey Public sign key of the user
     * @param mDataInfo Mutable data info as {@link MDataInfo}
     * @return {@link PermissionSet} for the user
     */
    public CompletableFuture<PermissionSet> getPermissionForUser(final NativeHandle publicSignKey,
                                                                 final MDataInfo mDataInfo) {
        final CompletableFuture<PermissionSet> future = new CompletableFuture<>();
        NativeBindings.mdataListUserPermissions(appHandle.toLong(), mDataInfo,
                publicSignKey.toLong(), (result, permissionSet) -> {
                    if (result.getErrorCode() != 0) {
                        future.completeExceptionally(Helper.ffiResultToException(result));
                    }
                    future.complete(permissionSet);
                });
        return future;
    }

    /**
     * Set the permissions for a user
     * @param publicSignKey Public sign key of the user as {@link NativeHandle}
     * @param mDataInfo Mutable data info as {@link MDataInfo}
     * @param permissionSet {@link PermissionSet} for the user
     * @param version The next version of the mutable data shell
     */
    public CompletableFuture<Void> setUserPermission(final NativeHandle publicSignKey, final MDataInfo mDataInfo,
                                                     final PermissionSet permissionSet, final long version) {
        final CompletableFuture<Void> future = new CompletableFuture<Void>();
        NativeBindings.mdataSetUserPermissions(appHandle.toLong(), mDataInfo,
                publicSignKey.toLong(), permissionSet, version, (result) -> {
                    if (result.getErrorCode() != 0) {
                        future.completeExceptionally(Helper.ffiResultToException(result));
                    }
                    future.complete(null);
                });
        return future;
    }

    /**
     * Delete the permissions given to a particular user
     * @param publicSignKey Public sign key of the user as {@link NativeHandle}
     * @param mDataInfo Mutable data info as {@link MDataInfo}
     * @param version Next version of the mutable data shell
     */
    public CompletableFuture<Void> deleteUserPermission(final NativeHandle publicSignKey, final MDataInfo mDataInfo,
                                                        final long version) {
        final CompletableFuture<Void> future = new CompletableFuture<Void>();
        NativeBindings.mdataDelUserPermissions(appHandle.toLong(), mDataInfo,
                publicSignKey.toLong(), version, (result) -> {
                    if (result.getErrorCode() != 0) {
                        future.completeExceptionally(Helper.ffiResultToException(result));
                    }
                    future.complete(null);
                });
        return future;
    }

    /**
     * Serialize metadata of the Mutable data
     * @param metadataResponse Metadata of the Mutable data
     * @return Serialized metadata of the MData
     */
    public CompletableFuture<byte[]> encodeMetadata(final MetadataResponse metadataResponse) {
        final CompletableFuture<byte[]> future = new CompletableFuture<>();
        NativeBindings.mdataEncodeMetadata(metadataResponse, (result, encodedMetadata) -> {
            if (result.getErrorCode() != 0) {
                future.completeExceptionally(Helper.ffiResultToException(result));
            }
            future.complete(encodedMetadata);
        });
        return future;
    }
}
