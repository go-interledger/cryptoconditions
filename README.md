# cryptoconditions

This package provides a Go (golang) implementation of the 
[Crypto-Conditions specification](https://datatracker.ietf.org/doc/draft-thomas-crypto-conditions/)
intended for the Interledger protocol.

## Considerations

 - Consider not exposing different fulfillment types. 
 
 They are immutable and have a clear API and constructor methods.
 
 => not possible because some fulfillments have specific interfaces
 
 - Let `Fulfillment.Validate(message)` return a boolean (and an error) instead of just an error.
 
 - Let `Fulfillment.Validate` also take a `Condition` as argument to verify if the fulfillment and the
 message fulfill the given condition. (Could be omitted when `nil` is passed.)
 
 - Divide different conditions and fulfillments into subpackages.
 
 - Allow for signing of RSA-SHA-256 conditions.
 
 - Use `int` instead of `uint32` for all weights and sizes in Threshold ff. 
 Could only check on interfaces. But using fixed-size types in structs allows for easier serialized storage, no?
 (See separate branch were I did this.)
 
 - Add serialization and URI round-trip tests to (fulfillment) standard tests. Could do for conditions too.
 
 - Perhaps some smaller considerations in TODO's in the code.

## Differences with InterledgerJs

 - Fulfillment objects are immutable, except for the `ParsePayload` method, used for deserialization.
 
 - No validation of conditions against local rules (JS's `condition.validate`).
 We could make a `LocalConstraints` struct with two validate methods in a separate file..
