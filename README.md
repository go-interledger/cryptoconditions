# cryptoconditions

This package provides a Go (golang) implementation of the 
[Crypto-Conditions specification](https://datatracker.ietf.org/doc/draft-thomas-crypto-conditions/)
intended for the Interledger protocol.

As the [InterledgerJS implementation](https://github.com/interledgerjs/five-bells-condition) of Crypto-Conditions is
considered the reference implementation, this package contains all unit tests from the JS implementation.

As you can read further below, the package is not finished yet. All implementation is provided, but not yet correct. 
Also, several improvement considerations have to be made.

## TODO

A few things don't work yet as they should (InterledgerJS vectors)

 - The `TestFfEd25519Vectors` tests generate wrong conditions.
 
 - The `TestFfRsaSha256Vectors` tests fail to verify the RSA signatures.
 
 - The `TestFfThresholdSha256Vectors` tests generate wrong conditions.
 
 - The `TestCalculateWorstCaseSffsLength` test generates wrong results.

## Considerations

 - Consider not exposing different fulfillment types. 
 
 They are immutable and have a clear API and constructor methods.
 
 => but some fulfillments have specific interfaces f.e. to query public keys, but these are theoretically not required
 
 - Divide different conditions and fulfillments into subpackages.
 
 - Let `Fulfillment.Validate(message)` return a boolean (and an error) instead of just an error.
 
 - Let `Fulfillment.Validate` also take a `Condition` as argument to verify if the fulfillment and the
 message fulfill the given condition. (Could be omitted when `nil` is passed.)
 
 - Allow for signing of RSA-SHA-256 and Ed255619 conditions.
 
 - Use `int` instead of `uint32` for all weights and sizes in Threshold ff. 
 Could only check on interfaces. But using fixed-size types in structs allows for easier serialized storage, no?
 (See separate branch were I did this. I'm currently not really in favor anymore.)
 
 - Add serialization and URI round-trip tests to (fulfillment) standard tests. Could do for conditions too.
 
 - Perhaps some smaller considerations in TODO's in the code.

## Differences with InterledgerJs

 - Fulfillment objects are immutable (at least after the `ParsePayload` method has been called when deserializing).
 
 - No validation of conditions against local rules (JS's `condition.validate`).
 We could make a `LocalConstraints` struct with two validate methods in a separate file..
 
 
 ## Licensing
 
 This implementation is part of the public domain. More information can be found in the `UNLICENSE` file.
