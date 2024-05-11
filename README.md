<!--
  -- Copyright 2023 Contributors to the Parsec project.
  -- SPDX-License-Identifier: Apache-2.0
  --
  -- Licensed under the Apache License, Version 2.0 (the "License"); you may
  -- not use this file except in compliance with the License.
  -- You may obtain a copy of the License at
  --
  -- http://www.apache.org/licenses/LICENSE-2.0
  --
  -- Unless required by applicable law or agreed to in writing, software
  -- distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
  -- WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  -- See the License for the specific language governing permissions and
  -- limitations under the License.
--->

# parsec-openssl-provider

Parsec OpenSSL Provider is an OpenSSL 3.x provider to access the Parsec Service for 
performing cryptographic operations using hardware backed keys. 

Learn more about Parsec [here](https://github.com/parallaxsecond/parsec). 

The provider should work with any version of the Parsec Service starting from 1.x.x
but it is recommended to use the latest available version.

# Build Prerequisites

- OpenSSL 3.x.x libraries and development headers

# Building the provider

Use the following commands to build a shared library of the parsec provider that can 
be dynamically loaded by openssl, 

```
cd parsec-openssl-provider-shared
cargo build
```

You should be able to find the provider <span style="background-color: #000000">libparsec_openssl_provider_shared.so</span> under
<span style="background-color: #000000">/parsec-openssl-provider/target/debug/</span>.

# Configuring the provider

The easiest way to load and run the provider is by using the openssl config file. You 
can add the following section to your existing config file,

```
[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
parsec = parsec_sect

[parsec_sect]
module = /path-to-shared-library/libparsec_openssl_provider_shared.so
activate = 1

[default_sect]
activate = 1
```

Once configured, you can list the providers loaded using the following command and ensure that parsec is loaded successfully. 

```
openssl list -providers
```

You can explicitly specify the provider in the above command instead of using the openssl config file as shown below,

```
openssl list -providers -provider-path /path/to/provider -provider libparsec_openssl_provider_shared
```

# License

The software is provided under Apache-2.0. Contributions to this project are accepted 
under the same license.
