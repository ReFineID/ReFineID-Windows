// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! The Windows `msroots` file: a PKCS#7 (CMS) certs-only bundle of
//! the DVV root/intermediate CAs.
//!
//! After reading the card's key-exchange and signature certificates
//! (`kscNN` / `kxcNN`), the Base CSP reads the special `msroots`
//! file to obtain the issuing CA chain as a PKCS#7 `SignedData` with
//! no signer -- exactly the convention `OpenSC`'s minidriver follows.
//! Windows uses it to build and validate the certificate chain.
//!
//! The bundle holds the public DVV `Citizen Certificates - G4R`
//! intermediate and the self-signed `DVV Gov. Root CA - G3 RSA`
//! root. Both are public CA certificates (the same anchors pinned in
//! `refineid-client`'s trust store); none of this is secret. It is
//! stored as an opaque binary asset and embedded at compile time,
//! matching the trust-anchor storage pattern used elsewhere in the
//! workspace, rather than as an in-source byte table.
#![expect(
    clippy::redundant_pub_crate,
    reason = "This private helper module still uses pub(crate) for consistency with the other minidriver support modules"
)]

/// PKCS#7 (CMS `SignedData`, certs-only) DER bytes served for the
/// Base CSP's `msroots` read. See the module docs for provenance.
pub(crate) const DVV_MSROOTS_PKCS7_DER: &[u8] = include_bytes!("../trust-anchors/dvv-msroots.p7b");
