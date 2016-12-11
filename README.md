# cryptoconditions

<<<<<<< HEAD
This package provides a Go (golang) implementation of the 
[Crypto-Conditions specification](https://datatracker.ietf.org/doc/draft-thomas-crypto-conditions/)
intended for the Interledger protocol.
=======

## Considerations

 - Consider not exposing different fulfillment types. 
 
 They are immutable and have a clear API and constructor methods.
 
 => not possible because some fulfillments have specific interfaces
 
 - Consider letting `Fulfillment.Validate(message)` return a boolean (and an error) instead of just an error.
 
 - Some smaller considerations in TODO's in the code.

## Differences with InterledgerJs

 - Fulfillment objects are immutable,
 except for the `ParsePayload` method.
 - No validation of conditions against local rules 
 (js's `condition.validate`).
>>>>>>> Initial implementation
