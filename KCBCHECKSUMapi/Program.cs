using System;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Net;
using RestSharp;
using Newtonsoft.Json;
using Nancy.Json;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;

namespace Test
{
    class Program
    {
        static string KCBRESPONSE = null;
        static string CheckSumResponse = null;
        static string Fileresponse = null;
        static string statusqueryResponse = null;
        static string QueryResponse = null;

        public static object encryptedFile { get; private set; }
        public static object systemCode { get; private set; }
        public static string transactionDate { get; private set; }

        static void Main(string[] args)
        {

            string path = @"C:\BTL\94424.txt";
            string fileName = Path.GetFileName(path);
            var fileStream = new FileStream(fileName, FileMode.OpenOrCreate, FileAccess.Read);
            var systemCode = "REDCROSS";
            var conversationId = "REDCROSS12";
            var serviceId = "REDCROSS";


            var encryptedFile = @"C:\Users\Admin2\Downloads\New folder\94424.txt.asc";

            string dataString = GetChecksumBuffered(fileStream);
            try
            {
                // Create a UnicodeEncoder to convert between byte array and string.
                ASCIIEncoding ByteConverter = new ASCIIEncoding();
                byte[] originalData = ByteConverter.GetBytes(dataString);
                byte[] signedData;
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();
                RSAParameters Key = RSAalg.ExportParameters(true);
                RSAParameters PublicKey = RSAalg.ExportParameters(false);

                // Hash and sign the data.
                signedData = HashAndSignBytes(originalData, Key);
                string base64 = Convert.ToBase64String(signedData, 0, signedData.Length);

                //coverting private key to string
                string privKey;
                {
                    //we need some buffer
                    var sw = new System.IO.StringWriter();
                    //we need a serializer
                    var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                    //serialize the key into the stream
                    xs.Serialize(sw, Key);
                    //get the string from the stream
                    privKey = sw.ToString();
                }
                string pubKey;
                {
                    //we need some buffer
                    var sw = new System.IO.StringWriter();
                    //we need a serializer
                    var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                    //serialize the key into the stream
                    xs.Serialize(sw, PublicKey);
                    //get the string from the stream
                    pubKey = sw.ToString();
                }
                string checksum = Encoding.Default.GetString(originalData);

                var sender = SendChecksum(checksum, base64, serviceId, systemCode, conversationId, fileName);
                // encrypt the data using gpg

                PGPEncryptDecrypt pgp = new PGPEncryptDecrypt();

                string passPhrase = "hello world!";

                //full path to file to encrypt
                string origfilePath = @"C:\BTL\94424.txt";
                string origFilePath = Path.GetFileName(origfilePath);
                //folder to store encrypted file
                string encryptedFilePath = @"C:\Users\Admin2\Downloads\New folder\";
                //folder to store unencrypted file
                string unencryptedFilePath = @"C:\Users\Admin2\Downloads\New folder\";
                //path to public key file 
                string publicKeyFile = @"C:\Users\Admin2\Downloads\New folder\REDCROSS.ASC";
                //string publicKeyFile = Path.GetFileName(publicKeyFilepath);
                //path to private key file (this file should be kept at client, AND in a secure place, far from prying eyes and tinkering hands)
                string privateKeyFile = @"C:\Users\Admin2\Downloads\New folder\REDCROSS.ASC";
                //string privateKeyFile = Path.GetFileName(privateKeyFilepath);
                pgp.Encrypt(origFilePath, publicKeyFile, encryptedFilePath);
                // pgp.Decrypt(encryptedFilePath + "credentials.txt.asc", privateKeyFile, passPhrase, unencryptedFilePath);
                string final_data = sendingFile(encryptedFile, systemCode);

                string report = null;


                // Verify the data and display the result to the console.
                if (VerifySignedHash(originalData, signedData, Key))
                {
                    //System.Console.WriteLine("Original Data: " + Encoding.Default.GetString(originalData));
                    //System.Console.WriteLine("Private Key: " + privKey);
                    //System.Console.WriteLine("Public Key: " + pubKey);
                    //System.Console.WriteLine("Signed data: " + Encoding.Default.GetString(signedData));
                    //System.Console.WriteLine("Signed data: " + base64);
                    //System.Console.WriteLine("The data was verified.");

                    System.Console.ReadLine();
                }

                else
                {
                    System.Console.WriteLine("The data does not match the signature.");
                    System.Console.ReadLine();
                }
            }
            catch (ArgumentNullException)
            {
                System.Console.WriteLine("The data was not signed or verified");
                System.Console.ReadLine();
            }
        }
        public static byte[] HashAndSignBytes(byte[] DataToSign, RSAParameters Key)

        {
            try
            {
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();

                RSAalg.ImportParameters(Key);

                // Hash and sign the data. Pass a new instance of SHA256 to specify the hashing algorithm.
                return RSAalg.SignData(DataToSign, SHA256.Create());
            }
            catch (CryptographicException e)
            {
                System.Console.WriteLine(e.Message);

                return null;
            }
        }
        public static bool VerifySignedHash(byte[] DataToVerify, byte[] SignedData, RSAParameters Key)
        {
            try
            {
                // Create a new instance of RSACryptoServiceProvider using the key from RSAParameters.
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();

                RSAalg.ImportParameters(Key);

                // Verify the data using the signature.  Pass a new instance of SHA256
                // to specify the hashing algorithm.
                return RSAalg.VerifyData(DataToVerify, SHA256.Create(), SignedData);
            }
            catch (CryptographicException e)
            {
                //Console..WriteLine(e.Message);

                return false;
            }
        }
        private static string GetChecksumBuffered(Stream stream)
        {
            using (var bufferedStream = new BufferedStream(stream, 1024 * 32))
            {
                var sha = new SHA256Managed();
                byte[] checksum = sha.ComputeHash(bufferedStream);
                return BitConverter.ToString(checksum).Replace("-", String.Empty);

            }
        }
        //Sending the file
        public static string sendingFile(string encryptedFile, string systemCode)
        {
            string token = Gettoken();
            token = "Bearer " + token;

            var client = new RestClient("https://196.216.223.2:4450/kcb/fileUpload/v1");
            client.Timeout = -1;
            var request = new RestRequest(Method.POST);
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Content-Type", "application/json");
            request.AddHeader("Authorization", token);
            request.AlwaysMultipartFormData = true;
            request.AddParameter("file", encryptedFile);
            request.AddParameter("SystemCode", systemCode);
            IRestResponse response = client.Execute(request);
            Fileresponse = response.Content;
            Console.WriteLine(response.Content);
            filesending Response = JsonConvert.DeserializeObject<filesending>(Fileresponse);
            var filestatus = Response.status;
            var report = Response.report;

            return report;
        }
        //Get token from KCB
        public static string Gettoken()
        {
            string Username = "REDCROSS101";
            string Password = "1520Suspect6?";
            string svcCredentials = Convert.ToBase64String(ASCIIEncoding.ASCII.GetBytes(Username + ":" + Password));
            System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            string auth = "Basic " + svcCredentials;

            var client = new RestClient("https://196.216.223.2:4450/kcb/payments/auth/v1");
            client.Timeout = -1;
            var request = new RestRequest(Method.POST);
            request.AddHeader("Content-Type", "application/json");
            request.AddHeader("Authorization", "Basic UkVEQ1JPU1MxMDE6MTUyMFN1c3BlY3Q2Pw==");
            IRestResponse response = client.Execute(request);
            KCBRESPONSE = response.Content;
            Console.WriteLine(response.Content);

            TokenResponse AccessTokenRequestResponse = JsonConvert.DeserializeObject<TokenResponse>(KCBRESPONSE);
            var Accesstoken = AccessTokenRequestResponse.access_token;

            return Accesstoken;
        }
        // send Signed Check sum
        public static string SendChecksum(string checksum, string signature, string serviceId, string systemCode, string conversationId, string fileName)
        {

            string token = Gettoken();
            token = "Bearer " + token;

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            var bodyRequest = new Sendchecksum
            {
                header = new Header
                {
                    conversationId = conversationId,
                    serviceId = serviceId,
                    systemCode = systemCode
                },
                payload = new Payload
                {
                    fileName = fileName,
                    checksum = checksum,
                    signature = signature

                }

            };

            JavaScriptSerializer js = new JavaScriptSerializer();
            string body = js.Serialize(bodyRequest);

            var client = new RestClient("https://196.216.223.2:4450/kcb/payments/validation/v1");
            client.Timeout = -1;
            var request = new RestRequest(Method.POST);
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Content-Type", "application/json");
            request.AddHeader("Authorization", token);
            request.AddParameter("application/json", body, ParameterType.RequestBody);
            IRestResponse response = client.Execute(request);
            CheckSumResponse = response.Content;
            Console.WriteLine(response.Content);

            checksumresponseBody RequestResponse = JsonConvert.DeserializeObject<checksumresponseBody>(CheckSumResponse);
            var status = RequestResponse.status;
            var description = RequestResponse.description;
            var ConversationId = RequestResponse.conversationId;
            var FileName = RequestResponse.fileName;
            var originatorConversationId = RequestResponse.originatorConversationId;
            var Status = RequestResponse.status;
            var submissionDate = RequestResponse.submissionDate;
            var totalFailed = RequestResponse.totalFailed;
            var totalNumberInFile = RequestResponse.totalNumberInFile;
            var totalSuccess = RequestResponse.totalSuccess;
            var transactionDate = RequestResponse.transactionDate;

            return description;
        }
        //sending the fileQuery
        public static string StatusQuery(string checksum, string signature, string serviceId, string systemCode, string conversationId, string fileName)
        {
            string token = Gettoken();
            token = "Bearer " + token;

            var bodyrequest = new statusquery
            {
                headerquery = new Headerquery
                {
                    conversationId = conversationId,
                    serviceId = serviceId,
                    systemCode =systemCode

                },
                payloadquery = new Payloadquery
                {
                    fileName = fileName,
                    transactionDate = transactionDate
                }
            };

            var client = new RestClient("https://196.216.223.2:4450/kcb/payments/query/v1");
            client.Timeout = -1;
            var request = new RestRequest(Method.POST);
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Content-Type", "application/json");
            request.AddHeader("Authorization",token);    
            request.AddParameter("application/json", bodyrequest, ParameterType.RequestBody);
            IRestResponse response = client.Execute(request);
            statusqueryResponse = response.Content;
            QueryResponse = response.Content;
            Console.WriteLine(response.Content);
            StatusReply queryResponse = JsonConvert.DeserializeObject<StatusReply>(Fileresponse);
            var status = queryResponse.status;
            var totalSuccess = queryResponse.totalSuccess;
            var fileNameQuery = queryResponse.fileName;

            return fileNameQuery;
        }
        public static void WriteLog(string text)
        {
            try
            {
                //set up a filestream
                string strPath = @"C:\Logs\KCBREDCROSS";
                string fileName = DateTime.Now.ToString("MMddyyyy") + "_logs.txt";
                string filenamePath = strPath + '\\' + fileName;
                Directory.CreateDirectory(strPath);
                FileStream fs = new FileStream(filenamePath, FileMode.OpenOrCreate, FileAccess.Write);
                //set up a streamwriter for adding text
                StreamWriter sw = new StreamWriter(fs);
                //find the end of the underlying filestream
                sw.BaseStream.Seek(0, SeekOrigin.End);
                //add the text
                sw.WriteLine(DateTime.Now.ToString() + " : " + text);
                //add the text to the underlying filestream
                sw.Flush();
                //close the writer
                sw.Close();
            }
            catch (Exception ex)
            {
                //throw;
                ex.Data.Clear();
            }
        }
    }
    public class PGPEncryptDecrypt
    {

        public PGPEncryptDecrypt()
        {

        }

        /**
        * A simple routine that opens a key ring file and loads the first available key suitable for
        * encryption.
        *
        * @param in
        * @return
        * @m_out
        * @
        */
        private static PgpPublicKey ReadPublicKey(Stream inputStream)
        {

            inputStream = PgpUtilities.GetDecoderStream(inputStream);
            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);
            //
            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            //
            //
            // iterate through the key rings.
            //
            foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
            {

                foreach (PgpPublicKey k in kRing.GetPublicKeys())
                {

                    if (k.IsEncryptionKey)
                    {

                        return k;

                    }


                }


            }

            throw new ArgumentException("Can't find encryption key in key ring.");

        }

        /**
        * Search a secret key ring collection for a secret key corresponding to
        * keyId if it exists.
        *
        * @param pgpSec a secret key ring collection.
        * @param keyId keyId we want.
        * @param pass passphrase to decrypt secret key with.
        * @return
        */
        private static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
        {

            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);
            if (pgpSecKey == null)
            {

                return null;

            }

            return pgpSecKey.ExtractPrivateKey(pass);

        }

        /**
        * decrypt the passed in message stream
        */
        private static void DecryptFile(Stream inputStream, Stream keyIn, char[] passwd, string defaultFileName, string pathToSaveFile)
        {

            inputStream = PgpUtilities.GetDecoderStream(inputStream);
            try
            {

                PgpObjectFactory pgpF = new PgpObjectFactory(inputStream);
                PgpEncryptedDataList enc;
                PgpObject o = pgpF.NextPgpObject();
                //
                // the first object might be a PGP marker packet.
                //
                if (o is PgpEncryptedDataList)
                {

                    enc = (PgpEncryptedDataList)o;

                }

                else
                {

                    enc = (PgpEncryptedDataList)pgpF.NextPgpObject();

                }

                //
                // find the secret key
                //
                PgpPrivateKey sKey = null;
                PgpPublicKeyEncryptedData pbe = null;
                PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(
                PgpUtilities.GetDecoderStream(keyIn));
                foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                {

                    sKey = FindSecretKey(pgpSec, pked.KeyId, passwd);
                    if (sKey != null)
                    {

                        pbe = pked;
                        break;

                    }


                }

                if (sKey == null)
                {

                    throw new ArgumentException("secret key for message not found.");

                }

                Stream clear = pbe.GetDataStream(sKey);
                PgpObjectFactory plainFact = new PgpObjectFactory(clear);
                PgpObject message = plainFact.NextPgpObject();
                if (message is PgpCompressedData)
                {

                    PgpCompressedData cData = (PgpCompressedData)message;
                    PgpObjectFactory pgpFact = new PgpObjectFactory(cData.GetDataStream());
                    message = pgpFact.NextPgpObject();

                }

                if (message is PgpLiteralData)
                {

                    PgpLiteralData ld = (PgpLiteralData)message;
                    string outFileName = ld.FileName;
                    if (outFileName.Length == 0)
                    {

                        outFileName = defaultFileName;

                    }

                    Stream fOut = File.Create(pathToSaveFile + outFileName);
                    Stream unc = ld.GetInputStream();
                    Streams.PipeAll(unc, fOut);
                    fOut.Close();

                }

                else if (message is PgpOnePassSignatureList)
                {

                    throw new PgpException("encrypted message contains a signed message - not literal data.");

                }

                else
                {

                    throw new PgpException("message is not a simple encrypted file - type unknown.");

                }

                if (pbe.IsIntegrityProtected())
                {

                    if (!pbe.Verify())
                    {

                        Console.Error.WriteLine("message failed integrity check");

                    }

                    else
                    {

                        Console.Error.WriteLine("message integrity check passed");

                    }


                }

                else
                {

                    Console.Error.WriteLine("no message integrity check");

                }


            }

            catch (PgpException e)
            {

                Console.Error.WriteLine(e);
                Exception underlyingException = e.InnerException;
                if (underlyingException != null)
                {

                    Console.Error.WriteLine(underlyingException.Message);
                    Console.Error.WriteLine(underlyingException.StackTrace);

                }


            }


        }

        private static void EncryptFile(Stream outputStream, string fileName, PgpPublicKey encKey, bool armor, bool withIntegrityCheck)
        {

            if (armor)
            {

                outputStream = new ArmoredOutputStream(outputStream);

            }

            try
            {

                MemoryStream bOut = new MemoryStream();
                PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(
                CompressionAlgorithmTag.Zip);
                PgpUtilities.WriteFileToLiteralData(
                comData.Open(bOut),
                PgpLiteralData.Binary,
                new FileInfo(fileName));
                comData.Close();
                PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(
                SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());
                cPk.AddMethod(encKey);
                byte[] bytes = bOut.ToArray();
                Stream cOut = cPk.Open(outputStream, bytes.Length);
                cOut.Write(bytes, 0, bytes.Length);
                cOut.Close();
                if (armor)
                {

                    outputStream.Close();

                }


            }

            catch (PgpException e)
            {

                Console.Error.WriteLine(e);
                Exception underlyingException = e.InnerException;
                if (underlyingException != null)
                {

                    Console.Error.WriteLine(underlyingException.Message);
                    Console.Error.WriteLine(underlyingException.StackTrace);

                }


            }


        }

        public void Encrypt(string filePath, string publicKeyFile, string pathToSaveFile)
        {

            Stream keyIn, fos;
            keyIn = File.OpenRead(publicKeyFile);
            string[] fileSplit = filePath.Split('\\');
            string fileName = fileSplit[fileSplit.Length - 1];
            fos = File.Create(pathToSaveFile + fileName + ".asc");
            EncryptFile(fos, filePath, ReadPublicKey(keyIn), true, true);
            keyIn.Close();
            fos.Close();

        }

        public void Decrypt(string filePath, string privateKeyFile, string passPhrase, string pathToSaveFile)
        {

            Stream fin = File.OpenRead(filePath);
            Stream keyIn = File.OpenRead(privateKeyFile);
            DecryptFile(fin, keyIn, passPhrase.ToCharArray(), new FileInfo(filePath).Name + ".out", pathToSaveFile);
            fin.Close();
            keyIn.Close();

        }


    }
    public class TokenResponse
    {
        public string access_token { get; set; }
        public string expires_in { get; set; }
        public string refresh_token { get; set; }
        public string token_type { get; set; }
        public string scope { get; set; }
    }
    public class checksumresponseBody
    {
        public int status { get; set; }
        public string description { get; set; }
        public string conversationId { get; set; }
        public string originatorConversationId { get; set; }
        public string fileName { get; set; }
        public DateTime transactionDate { get; set; }
        public DateTime submissionDate { get; set; }
        public int totalNumberInFile { get; set; }
        public int totalSuccess { get; set; }
        public int totalFailed { get; set; }

    }
    public class Sendchecksum
    {
        public Header header { get; set; }
        public Payload payload { get; set; }
    }
    public class Header
    {
        public string conversationId { get; set; }
        public string serviceId { get; set; }
        public string systemCode { get; set; }


    }
    public class Payload
    {
        public string checksum { get; set; }
        public string signature { get; set; }
        public string fileName { get; set; }


    }
    public class filesending
    {
        public string checksum { get; set; }
        public int status { get; set; }
        public string description { get; set; }
        public string conversationId { get; set; }
        public string originatorConversationId { get; set; }
        public string fileName { get; set; }
        public DateTime transactionDate { get; set; }
        public DateTime submissionDate { get; set; }
        public int totalNumberInFile { get; set; }
        public int totalSuccess { get; set; }
        public int totalFailed { get; set; }
        public string report { get; set; }

    }

    public class statusquery
    {
        public Headerquery headerquery { get; set; }
        public Payloadquery payloadquery { get; set; }
    }

    public class Headerquery
    {
        public string conversationId { get; set; }
        public string serviceId { get; set; }
        public string systemCode { get; set; }
    }

    public class Payloadquery
    {
        public string fileName { get; set; }
        public string transactionDate { get; set; }
    }

    public class StatusReply
    {
        public int status { get; set; }
        public string description { get; set; }
        public string conversationId { get; set; }
        public string originatorConversationId { get; set; }
        public string fileName { get; set; }
        public string checksum { get; set; }
        public DateTime transactionDate { get; set; }
        public DateTime submissionDate { get; set; }
        public int totalNumberInFile { get; set; }
        public int totalSuccess { get; set; }
        public int totalFailed { get; set; }
        public string statusquery { get; set; }
    }

   

}
