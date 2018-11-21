// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.
package net.maidsafe.api.model;

/***
 * Represents a Signing KeyPair
 */
public class SignKeyPair {

    private final NativeHandle publicSignKey;
    private final NativeHandle secretSignKey;

    /***
     * Initializes a SignKeyPair object
     * @param publicSignKey Public Signing Key
     * @param secretSignKey Private Signing Key
     */
    public SignKeyPair(final NativeHandle publicSignKey, final NativeHandle secretSignKey) {
        this.publicSignKey = publicSignKey;
        this.secretSignKey = secretSignKey;
    }

    /***
     * Returns the public signing key
     * @return Public sign key as {@link NativeHandle}
     */
    public NativeHandle getPublicSignKey() {
        return publicSignKey;
    }

    /***
     * Returns the secret signing Key
     * @return Secret sign key as {@link NativeHandle}
     */
    public NativeHandle getSecretSignKey() {
        return secretSignKey;
    }
}
