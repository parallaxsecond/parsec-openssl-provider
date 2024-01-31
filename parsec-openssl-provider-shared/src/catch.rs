// Copyright (c) Microsoft. All rights reserved.

/**
MIT License

Copyright (c) Microsoft Corporation. All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE
*/

// The function has been copied from https://github.com/Azure/iot-identity-service/blob/91e0588/key/aziot-key-openssl-engine/src/lib.rs#L98
// after getting the permission from the project maintainers.

/// Catches the error, if any, from evaluating the given callback and converts it to a unit sentinel.
/// If an openssl error function reference is provided, it is used to push the error onto the openssl error stack.
/// Otherwise, the error is logged to stderr.
///
/// Intended to be used at FFI boundaries, where a Rust error cannot pass through and must be converted to an integer, nullptr, etc.
use parsec_openssl_provider::openssl_errors;

pub fn r#catch<T>(
    function: Option<fn() -> openssl_errors::Function<super::Error>>,
    f: impl FnOnce() -> Result<T, Box<dyn std::error::Error>>,
) -> Result<T, ()> {
    match f() {
        Ok(value) => Ok(value),
        Err(err) => {
            // Technically, the order the errors should be put onto the openssl error stack is from root cause to top error.
            // Unfortunately this is backwards from how Rust errors work, since they are top error to root cause.
            //
            // We could do it the right way by collect()ing into a Vec<&dyn Error> and iterating it backwards,
            // but it seems too wasteful to be worth it. So just put them in the wrong order.

            if let Some(function) = function {
                openssl_errors::put_error!(function(), super::Error::MESSAGE, "{}", err);
            } else {
                eprintln!("[parsec-openssl-provider-shared] error: {}", err);
            }

            let mut source = err.source();
            while let Some(err) = source {
                if let Some(function) = function {
                    openssl_errors::put_error!(function(), super::Error::MESSAGE, "{}", err);
                } else {
                    eprintln!("[parsec-openssl-provider-shared] caused by: {}", err);
                }

                source = err.source();
            }

            Err(())
        }
    }
}
