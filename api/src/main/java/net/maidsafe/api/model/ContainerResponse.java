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
 * Represents an Authenticator Response object for a Container Request
 */
public class ContainerResponse extends DecodeResult {

    /***
     * Initializes a ContainerResponse object
     * @param reqId Request ID
     */
    public ContainerResponse(final int reqId) {
        super(reqId);
    }
}
