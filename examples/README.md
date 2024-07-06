# isomdl exmples

# Connection and data exchange between a device and a reader

```bash
 cargo run --package isomdl_examples --bin device_and_reader
```

This exemplifies a connection between a device and a reader.
The reader asks for `age_over_21` element and device responds with that value.
Flow is like this:
- device initializes with the mDL data, private and public keys
- device creates a QR code with `DeviceEngagement` data which contains it's public key also
- reader processes the QR code and creates a request for `age_over_21` element
  - also generating it's private an public keys and initiating key exchange and generates the session keys
  - the request is encrypted with the reader session key
- device receives the request and also initiates key exchange and generates the session keys
- device decrypts the request with reader's session key and create the response with `age_over_21` element encrypted with the device session key
- reader process the response and prints the value of `age_over_21` element

