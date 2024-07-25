# isomdl integration tests

Collection of integration tests that can be used as examples too of how you can use the library.

# Simulated device and reader interaction

This test demonstrates a simulated device and reader interaction.  
The reader requests the `age_over_21` element, and the device responds with that value.

```mermaid
sequenceDiagram
    autonumber
    Note over Device: Initialize session
    Device ->> Device: Create QR Code Engagement
    Device -) + Reader: Send QR Code
    Reader ->> - Reader: Establish Session
    Reader -) + Device: Request age_over_21
    Device -)- Reader: Send age_over_21
    Reader ->> Reader: Process age_over_21
    Note over Device, Reader: Session finished
```

## The flow of the interaction

1. **Device initialization and engagement:**
    - The device creates a QR code containing `DeviceEngagement` data, which includes its public key.
    - Internally:
        - The device initializes with the mDL data, private key, and public key.
2. **Reader processing QR and requesting needed fields:**
    - The reader processes the QR code and creates a request for the `age_over_21` element.
    - Internally:
        - Generates its private and public keys.
        - Initiates a key exchange, and generates the session keys.
        - The request is encrypted with the reader's session key.
3. **Device accepting request and responding:**
    - The device receives the request and creates a response with the `age_over_21` element.
    - Internally:
        - Initiates the key exchange, and generates the session keys.
        - Decrypts the request with the reader's session key.
        - Parse and validate it creating error response if needed.
        - The response is encrypted with the device's session key.
4. **Reader Processing mDL data:**
    - The reader processes the response and prints the value of the `age_over_21` element.

### Device perspective

There are several states through which the device goes during the interaction:

```mermaid
stateDiagram
    state Device {
        [*] --> SessionManagerInit: initialise
        SessionManagerInit --> SessionManagerEngaged: qr_engagement
        SessionManagerEngaged --> SessionManager: process_session_establishment
    }

    state SessionManagerInit {
        [*] --> [*]
    }

    state SessionManagerEngaged {
        [*] --> [*]
    }

    state Reader {
        [*] --> [*]
    }

    state SessionManager {
        [*] --> AwaitingRequest
        AwaitingRequest --> Signing: prepare_response
        Signing --> Signing: get_next_signature_payload
        Signing --> ReadyToRespond: submit_next_signature
        ReadyToRespond --> AwaitingRequest: retrieve_response
        AwaitingRequest --> Signing: handle_request
    }

    User --> Device
    SessionManagerInit --> Reader: qr_engagement
    Reader --> SessionManagerEngaged: establish_session
    ReadyToRespond --> Reader: handle_response
```

##### Reader perspective

From the reader's perspective, the flow is simpler:

```mermaid
stateDiagram
    state Device {
        [*] --> [*]
    }

    state Reader {
        SessionManager --> SessionManager: handle_response
    }

    User --> Device
    Device --> Reader: qr_engagement
    Reader --> Device: establish_session
    Device --> Reader
    Reader --> Device: new_request
```

There are several tests:

- full flow of the interaction:
    - in a basic structure [simulated_device_and_reader](simulated_device_and_reader.rs)
    - more organized structure using `State` pattern, `Arc`
      and `Mutex` [simulated_device_and_reader_state](simulated_device_and_reader_state.rs)
- on the device perspective [on_simulated_device](on_simulated_device.rs)
- on the reader perspective [on_simulated_reader](on_simulated_reader.rs)
