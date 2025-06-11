// Secure P2P Encrypted Chat with PGP Key Exchange + AES Key Rotation (Hacking-Style, C#)

using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.IO;
using System.Runtime.InteropServices.ComTypes;

class PGPChat
{
    static string aesKey = null;
    static PgpPublicKey clientPubKey;
    static PgpPrivateKey clientPrivKey;

    static void Main()
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(@"    ____                  _   _   _                    ");
        Console.WriteLine(@"  / ___|_ __ _   _ _ __ | |_| \ | | _____  ___   _ ___ ");
        Console.WriteLine(@" | |   | '__| | | | '_ \| __|  \| |/ _ \ \/ / | | / __|");
        Console.WriteLine(@" | |___| |  | |_| | |_) | |_| |\  |  __/>  <| |_| \__ \");
        Console.WriteLine(@"  \____|_|   \__, | .__/ \__|_| \_|\___/_/\_\\__,_|___/");
        Console.WriteLine(@"             |___/|_|                                  ");
        Console.ResetColor();
        Console.WriteLine("\nStart as (s)erver or (c)lient?");
        string role = Console.ReadLine();

        if (role.ToLower() == "s")
            StartServer();
        else if (role.ToLower() == "c")
            StartClient();
        else
            Console.WriteLine("Invalid input. Exiting.");
    }

    static void StartServer()
    {
        TcpListener listener = new TcpListener(IPAddress.Any, 5000);
        listener.Start();
        Console.WriteLine("[Server] Waiting for client to connect...");
        TcpClient client = listener.AcceptTcpClient();

        // Εμφάνιση IP client
        IPEndPoint remoteIpEndPoint = client.Client.RemoteEndPoint as IPEndPoint;
        Console.WriteLine($"[Server] Client connected! IP: {remoteIpEndPoint.Address}");

        using (NetworkStream ns = client.GetStream())
        using (BinaryReader reader = new BinaryReader(ns))
        using (BinaryWriter writer = new BinaryWriter(ns))
        {
            // Διαβάζουμε το public key του client
            byte[] clientPubKeyBytes = reader.ReadBytes(reader.ReadInt32());
            clientPubKey = ReadPublicKey(clientPubKeyBytes);

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[Server] Received client's PGP public key.");
            Console.ResetColor();

            // Δημιουργούμε το AES key και το στέλνουμε κρυπτογραφημένο
            aesKey = GenerateAESKey();
            byte[] encryptedKey = EncryptPGP(aesKey, clientPubKey);
            writer.Write(encryptedKey.Length);
            writer.Write(encryptedKey);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[Server] AES session key sent securely to client.");
            Console.WriteLine("[Server] Secure Channel Enabled.");
            Console.ResetColor();

            StartChat(ns, writer, isServer: true);
        }
    }

    static void StartClient()
    {
        Console.Write("Enter server IP address: ");
        string ip = Console.ReadLine();

        TcpClient client = new TcpClient();

        try
        {
            client.Connect(ip, 5000);
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[Client] Connection failed: {ex.Message}");
            Console.ResetColor();
            return;  // Τερματίζει την μέθοδο και άρα το πρόγραμμα μετά το Main
        }

        Console.WriteLine("[Client] Connected to server!");

        GeneratePGPKeyPair(out clientPubKey, out clientPrivKey);
        byte[] pubKeyBytes = ExportPublicKey(clientPubKey);

        using (NetworkStream ns = client.GetStream())
        using (BinaryWriter writer = new BinaryWriter(ns))
        using (BinaryReader reader = new BinaryReader(ns))
        {
            // Στέλνουμε το public key στον server
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[Client] Sending PGP public key to server...");
            writer.Write(pubKeyBytes.Length);
            writer.Write(pubKeyBytes);
            Console.WriteLine("[Client] Public key sent.");
            Console.ResetColor();

            // Λαμβάνουμε το κρυπτογραφημένο AES key
            byte[] encryptedKey = reader.ReadBytes(reader.ReadInt32());
            aesKey = DecryptPGP(encryptedKey, clientPrivKey);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[Client] Received AES session key.");
            Console.WriteLine("[Client] Secure Channel Enabled.");
            Console.ResetColor();

            StartChat(ns, null, isServer: false);
        }
    }


    static void StartChat(NetworkStream stream, BinaryWriter writer, bool isServer)
    {
        bool chatActive = true;

        Thread recvThread = new Thread(() =>
        {
            using (StreamReader reader = new StreamReader(stream))
            {
                while (chatActive)
                {
                    string encrypted = reader.ReadLine();
                    if (!string.IsNullOrEmpty(encrypted))
                    {
                        if (!isServer && encrypted.StartsWith("@@ROTATE@@"))
                        {
                            // Client λαμβάνει νέο AES κλειδί
                            string b64 = encrypted.Replace("@@ROTATE@@", "");
                            byte[] encKey = Convert.FromBase64String(b64);
                            aesKey = DecryptPGP(encKey, clientPrivKey);
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.WriteLine("[Client] 🔁 AES key updated (rotation).");
                            Console.ResetColor();
                        }
                        else
                        {
                            string decrypted = DecryptAES(encrypted, aesKey);

                            // Έλεγχος για !exit μήνυμα
                            if (decrypted == "!exit")
                            {
                                if (isServer)
                                {
                                    Console.ForegroundColor = ConsoleColor.Red;
                                    Console.WriteLine("[Server] Client has left the chat.");
                                    Console.ResetColor();
                                }
                                chatActive = false;
                                break;
                            }

                            Console.ForegroundColor = ConsoleColor.Cyan;
                            Console.WriteLine("\n[Received] " + decrypted);
                            Console.ResetColor();
                        }
                    }
                }
            }
        });
        recvThread.IsBackground = true;
        recvThread.Start();

        StreamWriter swriter = new StreamWriter(stream) { AutoFlush = true };

        if (isServer)
        {
            while (chatActive)
            {
                string msg = Console.ReadLine();

                if (msg == "/rotate")
                {
                    aesKey = GenerateAESKey();
                    byte[] encryptedKey = EncryptPGP(aesKey, clientPubKey);
                    string rotMsg = "@@ROTATE@@" + Convert.ToBase64String(encryptedKey);
                    swriter.WriteLine(rotMsg);
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("[Server] 🔁 AES key rotated and sent to client.");
                    Console.ResetColor();
                }
                else if (msg == "!exit")
                {
                    // Στέλνουμε και τερματίζουμε chat
                    string enc = EncryptAES(msg, aesKey);
                    swriter.WriteLine(enc);

                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[Server] You left the chat.");
                    Console.ResetColor();

                    chatActive = false;
                    break;
                }
                else
                {
                    string enc = EncryptAES(msg, aesKey);
                    swriter.WriteLine(enc);
                }
            }
        }
        else
        {
            while (chatActive)
            {
                string msg = Console.ReadLine();

                if (msg == "!exit")
                {
                    string enc = EncryptAES(msg, aesKey);
                    swriter.WriteLine(enc);

                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[Client] You left the chat.");
                    Console.ResetColor();

                    chatActive = false;
                    break;
                }

                string encMsg = EncryptAES(msg, aesKey);
                swriter.WriteLine(encMsg);
            }
        }

        // Κλείσιμο σύνδεσης
        stream.Close();
    }


    static string GenerateAESKey()
    {
        using (Aes aes = Aes.Create())
        {
            aes.KeySize = 128;
            aes.GenerateKey();
            return Convert.ToBase64String(aes.Key);
        }
    }

    static string EncryptAES(string plain, string keyBase64)
    {
        byte[] key = Convert.FromBase64String(keyBase64);
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.GenerateIV();
            using (var ms = new MemoryStream())
            {
                ms.Write(aes.IV, 0, aes.IV.Length); // Αποθήκευση IV στην αρχή
                using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] data = Encoding.UTF8.GetBytes(plain);
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();
                }
                return Convert.ToBase64String(ms.ToArray());
            }
        }
    }

    static string DecryptAES(string cipher, string keyBase64)
    {
        byte[] key = Convert.FromBase64String(keyBase64);
        byte[] fullCipher = Convert.FromBase64String(cipher);
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            byte[] iv = new byte[16];
            Array.Copy(fullCipher, 0, iv, 0, iv.Length);
            aes.IV = iv;

            using (var ms = new MemoryStream())
            {
                ms.Write(fullCipher, iv.Length, fullCipher.Length - iv.Length);
                ms.Position = 0;
                using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                using (var sr = new StreamReader(cs))
                {
                    return sr.ReadToEnd();
                }
            }
        }
    }


    static void GeneratePGPKeyPair(out PgpPublicKey publicKey, out PgpPrivateKey privateKey)
    {
        var rsaGen = new RsaKeyPairGenerator();
        rsaGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        AsymmetricCipherKeyPair kp = rsaGen.GenerateKeyPair();

        var now = DateTime.UtcNow;
        PgpKeyPair pgpKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, kp, now);

        publicKey = pgpKeyPair.PublicKey;
        privateKey = pgpKeyPair.PrivateKey;
    }

    static byte[] ExportPublicKey(PgpPublicKey publicKey)
    {
        using (MemoryStream ms = new MemoryStream())
        {
            publicKey.Encode(ms);
            return ms.ToArray();
        }
    }

    static PgpPublicKey ReadPublicKey(byte[] data)
    {
        using (MemoryStream ms = new MemoryStream(data))
        {
            PgpPublicKeyRingBundle bundle = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(ms));
            foreach (PgpPublicKeyRing ring in bundle.GetKeyRings())
            {
                foreach (PgpPublicKey key in ring.GetPublicKeys())
                {
                    if (key.IsEncryptionKey)
                        return key;
                }
            }
        }
        throw new Exception("No encryption key found in public key data");
    }

    static byte[] EncryptPGP(string plain, PgpPublicKey pubKey)
    {
        byte[] clear = Encoding.UTF8.GetBytes(plain);
        using (MemoryStream bOut = new MemoryStream())
        using (Stream outStream = new ArmoredOutputStream(bOut))
        {
            PgpEncryptedDataGenerator encGen = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128, true, new SecureRandom());
            encGen.AddMethod(pubKey);

            using (Stream encOut = encGen.Open(outStream, clear.Length))
            {
                encOut.Write(clear, 0, clear.Length);
            }
            outStream.Close();
            return bOut.ToArray();
        }
    }

    static string DecryptPGP(byte[] encrypted, PgpPrivateKey privKey)
    {
        using (MemoryStream inputStream = new MemoryStream(encrypted))
        using (Stream decoder = PgpUtilities.GetDecoderStream(inputStream))
        {
            PgpObjectFactory pgpF = new PgpObjectFactory(decoder);
            PgpEncryptedDataList enc;
            object o = pgpF.NextPgpObject();
            if (o is PgpEncryptedDataList list) enc = list;
            else enc = (PgpEncryptedDataList)pgpF.NextPgpObject();

            foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
            {
                using (Stream clear = pked.GetDataStream(privKey))
                using (MemoryStream plain = new MemoryStream())
                {
                    Streams.PipeAll(clear, plain);
                    return Encoding.UTF8.GetString(plain.ToArray());
                }
            }
        }
        throw new Exception("Failed to decrypt PGP message");
    }
}
