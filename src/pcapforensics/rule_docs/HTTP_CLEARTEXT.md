# HTTP_CLEARTEXT

## What it means
An HTTP exchange crossed the network without TLS. Severity is high when a request path looks like a firmware or package download (for example `/firmware/v2.1.bin`, `.img`, `.hex`, `.ipk`, `.swu`) and medium otherwise; the path is the signal because the capture model does not keep the content type.

## Why it matters
Everything in plain HTTP is readable and modifiable on-path: URLs, headers, cookies and bodies. For a firmware or package download an attacker on the network can replace the image in transit, and a device that installs it without checking a signature runs the attacker's code (CWE-494).

## How to fix
- Serve the endpoint over HTTPS (TLS 1.2 or newer) with certificate validation on the client, and redirect or refuse plain HTTP.
- For firmware and packages, also sign every image and verify the signature on the device before installing it; transport security protects the download, not the image.

## How to verify
Capture the traffic again and run `pcap-doctor analyze <capture>`; HTTP_CLEARTEXT must not be reported, and the flow in `01-flows.md` must show as encrypted.
