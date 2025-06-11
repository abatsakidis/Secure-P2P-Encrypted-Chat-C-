# Secure P2P Encrypted Chat (C#)

A simple peer-to-peer (P2P) encrypted chat application implemented in C#, featuring PGP public key exchange and AES session key encryption with key rotation support. This project demonstrates fundamental cryptographic concepts in a practical chat scenario.

---

## Features

- **PGP-based key exchange**  
  Securely exchange AES session keys using PGP asymmetric encryption.

- **AES symmetric encryption**  
  Encrypt chat messages with AES-128 for fast and secure communication.

- **AES key rotation**  
  Server can rotate the AES key on demand during a chat session, improving security.

- **Client and Server roles**  
  The application supports both server and client modes.

- **Graceful connection error handling**  
  Client shows an error message and exits if the server IP is invalid or unreachable.

- **Exit command support**  
  Users can type `!exit` to end the chat session cleanly.

---

## How to Use

1. **Build the project**  
   Compile the C# source code with your preferred IDE or the command line.

2. **Run the executable**  
   Start the application and select your role:

   - Enter `s` to start as **Server**
   - Enter `c` to start as **Client**

3. **If Server:**  
   - Wait for the client to connect.
   - The server will generate an AES session key and send it securely to the client.
   - Start chatting!

4. **If Client:**  
   - Enter the server's IP address when prompted.
   - The client will generate a PGP key pair and send its public key to the server.
   - Receive the AES session key securely and start chatting!

5. **During Chat:**  
   - Send messages securely encrypted with AES.
   - Server can rotate the AES key by typing `/rotate`.
   - Type `!exit` to leave the chat.

---

## Dependencies

- [BouncyCastle](https://www.bouncycastle.org/csharp/index.html) for PGP and cryptographic operations.

---

## Notes

- This is a simple demonstration project and should be enhanced before use in production.
- The AES key size is 128 bits for compatibility and speed, but can be increased.
- User authentication and trust verification of PGP keys are not implemented here.

---

## License

This project is provided as-is without warranty. Use at your own risk.

---

Happy secure chatting! 🚀
