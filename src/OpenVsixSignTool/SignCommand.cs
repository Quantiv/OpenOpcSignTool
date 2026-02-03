using System;
using System.CommandLine;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Security.KeyVault.Keys.Cryptography;
using OpenVsixSignTool.Core;

namespace OpenVsixSignTool
{
    internal static class SignCommand
    {
        public static Command Create()
        {
            var command = new Command("sign", "Sign a VSIX package");

            var vsixFileArgument = new Argument<FileInfo>("vsixFile")
            {
                Description = "The VSIX file to sign.",
                Arity = ArgumentArity.ExactlyOne
            };
            command.Arguments.Add(vsixFileArgument);

            var sha1Option = new Option<string>("--sha1", "-s")
            {
                Description = "A hex-encoded SHA-1 thumbprint of the certificate used to perform the signature.",
                Arity = ArgumentArity.ZeroOrOne
            };
            command.Options.Add(sha1Option);

            var certificateOption = new Option<FileInfo>("--certificate", "-c")
            {
                Description = "A path to a PFX file to perform the signature.",
                Arity = ArgumentArity.ZeroOrOne
            };
            command.Options.Add(certificateOption);

            var passwordOption = new Option<string>("--password", "-p")
            {
                Description = "The password for the PFX file.",
                Arity = ArgumentArity.ZeroOrOne
            };
            command.Options.Add(passwordOption);

            var timestampOption = new Option<string>("--timestamp", "-t")
            {
                Description = "A URL of the timestamping server to timestamp the signature.",
                Arity = ArgumentArity.ZeroOrOne
            };
            timestampOption.Validators.Add(result =>
            {
                var value = result.GetValue(timestampOption);
                if (ParseUri(result.GetValue(timestampOption)) == null)
                {
                    result.AddError("Specified timestamp URL is invalid.");
                }
            });
            command.Options.Add(timestampOption);

            var timestampAlgorithmOption = new Option<string>("--timestamp-algorithm", "-ta")
            {
                Description = "The digest algorithm of the timestamp.",
                Arity = ArgumentArity.ZeroOrOne,
                DefaultValueFactory = _ => "sha256"
            };
            timestampAlgorithmOption.Validators.Add(result =>
            {
                if (ParseHashAlgorithmName(result.GetValue(timestampAlgorithmOption)) == null)
                {
                    result.AddError("Specified timestamp digest algorithm is not supported.");
                }
            });
            command.Options.Add(timestampAlgorithmOption);

            var fileDigestOption = new Option<string>("--file-digest", "-fd")
            {
                Description = "The digest algorithm to hash the VSIX file with.",
                Arity = ArgumentArity.ZeroOrOne,
                DefaultValueFactory = _ => "sha256"
            };
            fileDigestOption.Validators.Add(result =>
            {
                if (ParseHashAlgorithmName(result.GetValue(fileDigestOption)) == null)
                {
                    result.AddError("Specified file digest algorithm is not supported.");
                }
            });
            command.Options.Add(fileDigestOption);

            var forceOption = new Option<bool>("--force", "-f")
            {
                Description = "Force the signature by overwriting any existing signatures.",
            };
            command.Options.Add(forceOption);

            var azureKeyVaultUrlOption = new Option<string>("--azure-key-vault-url", "-kvu")
            {
                Description = "The URL to an Azure Key Vault.",
                Arity = ArgumentArity.ZeroOrOne
            };
            azureKeyVaultUrlOption.Validators.Add(result =>
            {
                if (ParseUri(result.GetValue(azureKeyVaultUrlOption)) == null)
                {
                    result.AddError("Specified Azure Key Vault URL is invalid.");
                }
            });
            command.Options.Add(azureKeyVaultUrlOption);

            var azureKeyVaultClientIdOption = new Option<string>("--azure-key-vault-client-id", "-kvi")
            {
                Description = "The Client ID to authenticate to the Azure Key Vault.",
                Arity = ArgumentArity.ZeroOrOne
            };
            command.Options.Add(azureKeyVaultClientIdOption);

            var azureKeyVaultClientSecretOption = new Option<string>("--azure-key-vault-client-secret", "-kvs")
            {
                Description = "The Client Secret to authenticate to the Azure Key Vault.",
                Arity = ArgumentArity.ZeroOrOne
            };
            command.Options.Add(azureKeyVaultClientSecretOption);

            var azureKeyVaultTenantIdOption = new Option<string>("--azure-key-vault-tenant-id", "-kvt")
            {
                Description = "The Tenant Id to authenticate to the Azure Key Vault.",
                Arity = ArgumentArity.ZeroOrOne
            };
            command.Options.Add(azureKeyVaultTenantIdOption);

            var azureKeyVaultCertificateNameOption = new Option<string>("--azure-key-vault-certificate", "-kvc")
            {
                Description = "The name of the certificate in Azure Key Vault.",
                Arity = ArgumentArity.ZeroOrOne
            };
            command.Options.Add(azureKeyVaultCertificateNameOption);

            var azureKeyVaultCertificateVersionOption = new Option<string>("--azure-key-vault-certificate-version", "-kvcv")
            {
                Description = "The version of the certificate in Azure Key Vault to use. The current version of the certificate is used by default.",
                Arity = ArgumentArity.ZeroOrOne
            };
            command.Options.Add(azureKeyVaultCertificateVersionOption);

            var azureKeyVaultAccessTokenOption = new Option<string>("--azure-key-vault-accesstoken", "-kva")
            {
                Description = "The Access Token to authenticate to the Azure Key Vault.",
                Arity = ArgumentArity.ZeroOrOne
            };
            command.Options.Add(azureKeyVaultAccessTokenOption);

            var azureKeyVaultManagedIdentityOption = new Option<bool>("--azure-key-vault-managed-identity", "-kvm")
            {
                Description = "Use the current Azure managed identity."
            };
            command.Options.Add(azureKeyVaultManagedIdentityOption);

            var azureAuthorityOption = new Option<string>("--azure-authority", "-au")
            {
                Description = "The Azure Authority for Azure Key Vault.",
                Arity = ArgumentArity.ZeroOrOne
            };
            command.Options.Add(azureAuthorityOption);

            command.SetAction(async (parseResult, cancellationToken) =>
            {
                var vsixFile = parseResult.GetValue(vsixFileArgument);
                var vsixFilePath = vsixFile.FullName;
                if (!File.Exists(vsixFilePath))
                {
                    Console.Error.WriteLine("Specified VSIX file does not exist.");
                    return 2;
                }
                var sha1 = parseResult.GetValue(sha1Option);
                var certificate = parseResult.GetValue(certificateOption);
                var azureKeyVaultUrl = parseResult.GetValue(azureKeyVaultUrlOption);
                if ((sha1 == null) && (certificate == null) && (azureKeyVaultUrl == null))
                {
                    Console.Error.WriteLine("At least one of the options --sha1, --certificate or --azure-key-vault-url must be provided for signing.");
                    return 1;
                }
                if (((sha1 != null) && (certificate != null)) || ((sha1 != null) && (azureKeyVaultUrl == null)) || ((certificate != null) && (azureKeyVaultUrl != null)))
                {
                    Console.Error.WriteLine("Only one of the options --sha1, --certificate or --azure-key-vault-url can be provided for signing.");
                    return 1;
                }
                if ((sha1 != null) || (certificate != null))
                {
                    return await SignAsync
                    (
                        vsixFilePath,
                        sha1,
                        certificate?.FullName,
                        parseResult.GetValue(passwordOption),
                        parseResult.GetValue(timestampOption),
                        parseResult.GetValue(timestampAlgorithmOption),
                        parseResult.GetValue(fileDigestOption),
                        parseResult.GetValue(forceOption)
                    );
                }
                else
                {
                    return await SignAzureAsync
                    (
                        vsixFilePath,
                        azureKeyVaultUrl,
                        parseResult.GetValue(azureKeyVaultClientIdOption),
                        parseResult.GetValue(azureKeyVaultClientSecretOption),
                        parseResult.GetValue(azureKeyVaultTenantIdOption),
                        parseResult.GetValue(azureKeyVaultCertificateNameOption),
                        parseResult.GetValue(azureKeyVaultCertificateVersionOption),
                        parseResult.GetValue(azureKeyVaultAccessTokenOption),
                        parseResult.GetValue(azureKeyVaultManagedIdentityOption),
                        parseResult.GetValue(azureAuthorityOption),
                        parseResult.GetValue(forceOption),
                        parseResult.GetValue(fileDigestOption),
                        parseResult.GetValue(timestampOption),
                        parseResult.GetValue(timestampAlgorithmOption)
                    );
                }
            });

            return command;
        }

        private static HashAlgorithmName? ParseHashAlgorithmName(string value)
        {
            return (value?.ToLower()) switch
            {
                "sha1" => (HashAlgorithmName?)HashAlgorithmName.SHA1,
                "sha256" => (HashAlgorithmName?)HashAlgorithmName.SHA256,
                "sha384" => (HashAlgorithmName?)HashAlgorithmName.SHA384,
                "sha512" => (HashAlgorithmName?)HashAlgorithmName.SHA512,
                _ => null,
            };
        }

        private static Uri ParseUri(string value)
        {
            if (value != null)
            {
                if (Uri.TryCreate(value, UriKind.Absolute, out var uri))
                {
                    if ((uri.Scheme == Uri.UriSchemeHttp) || (uri.Scheme == Uri.UriSchemeHttps))
                    {
                        return uri;
                    }
                }
            }
            return null;
        }

        private static async ValueTask<int> SignAsync
        (
            string vsixFilePath,
            string sha1,
            string pfxFilePath,
            string password,
            string timestampUrl,
            string timestampAlgorithm,
            string fileDigest,
            bool force
        )
        {
            X509Certificate2 certificate;
            if (sha1 != null)
            {
                certificate = GetCertificateFromCertificateStore(sha1);
                if (certificate == null)
                {
                    Console.Error.WriteLine("Unable to locate certificate by thumbprint.");
                    return 2;
                }
            }
            else
            {
                if (!File.Exists(pfxFilePath))
                {
                    Console.Error.WriteLine("Specified PFX file does not exist.");
                    return 1;
                }
                certificate = X509CertificateLoader.LoadPkcs12FromFile(pfxFilePath, password);
            }
            Uri timestampServer = null;
            if (timestampUrl != null)
            {
                timestampServer = ParseUri(timestampUrl);
                if (timestampServer == null)
                {
                    Console.Error.WriteLine("Specified timestamp URL is invalid.");
                    return 2;
                }
            }
            var fileDigestAlgorithm = ParseHashAlgorithmName(fileDigest);
            if (!fileDigestAlgorithm.HasValue)
            {
                Console.Error.WriteLine("Specified file digest algorithm is not supported.");
                return 1;
            }
            var timestampDigestAlgorithm = ParseHashAlgorithmName(timestampAlgorithm);
            if (!timestampDigestAlgorithm.HasValue)
            {
                Console.Error.WriteLine("Specified timestamp digest algorithm is not supported.");
                return 1;
            }
            return await PerformSignOnVsixAsync
            (
                vsixFilePath,
                force,
                timestampServer,
                fileDigestAlgorithm.Value,
                timestampDigestAlgorithm.Value,
                certificate,
                GetSigningKeyFromCertificate(certificate)
            );
        }

        private static async ValueTask<int> SignAzureAsync
        (
            string vsixFilePath,
            string azureKeyVaultUrl,
            string azureKeyVaultClientId,
            string azureKeyVaultClientSecret,
            string azureKeyVaultTenantId,
            string azureKeyVaultCertificateName,
            string azureKeyVaultCertificateVersion,
            string azureKeyVaultAccessToken,
            bool azureKeyVaultManagedIdentity,
            string azureAuthority,
            bool force, 
            string fileDigest,
            string timestampUrl, 
            string timestampAlgorithm
        )
        {
            var keyVaultUrl = ParseUri(azureKeyVaultUrl);
            if (keyVaultUrl == null)
            {
                Console.Error.WriteLine("The specified Azure Key Vault URL is invalid.");
            }
            if ((!azureKeyVaultManagedIdentity) && (azureKeyVaultAccessToken == null) && (azureKeyVaultClientId == null))
            {
                Console.Error.WriteLine("At least one of --azure-key-vault-managed-identity, --azure-key-vault-accesstoken or --azure-key-vault-client-id must be specified for Azure signing.");
                return 1;
            }
            if (azureKeyVaultClientId != null)
            {
                if (azureKeyVaultClientSecret == null)
                {
                    Console.Error.WriteLine("--azure-key-vault-client-secret must be specified if --azure-key-vault-client-id is specified for Azure signing.");
                    return 1;
                }
                if (azureKeyVaultTenantId == null)
                {
                    Console.Error.WriteLine("--azure-key-vault-tenant-id must be specified if --azure-key-vault-client-id is specified for Azure signing.");
                    return 1;
                }
            }
            if (azureKeyVaultCertificateName == null)
            {
                Console.Error.WriteLine("--azure-key-vault-certificate must be specified for Azure signing.");
                return 1;
            }

            Uri timestampServer = null;
            if (timestampUrl != null)
            {
                timestampServer = ParseUri(timestampUrl);
                if (timestampServer == null)
                {
                    Console.Error.WriteLine("Specified timestamp URL is invalid.");
                    return 2;
                }
            }
            var fileDigestAlgorithm = ParseHashAlgorithmName(fileDigest);
            if (!fileDigestAlgorithm.HasValue)
            {
                Console.Error.WriteLine("Specified file digest algorithm is not supported.");
                return 1;
            }
            var timestampDigestAlgorithm = ParseHashAlgorithmName(timestampAlgorithm);
            if (!timestampDigestAlgorithm.HasValue)
            {
                Console.Error.WriteLine("Specified timestamp digest algorithm is not supported.");
                return 1;
            }

            var configuration = new AzureKeyVaultSignConfigurationSet
            {
                AzureKeyVaultUrl = keyVaultUrl,
                AzureKeyVaultCertificateName = azureKeyVaultCertificateName,
                AzureKeyVaultCertificateVersion = azureKeyVaultCertificateVersion,
                AzureClientId = azureKeyVaultClientId,
                AzureTenantId = azureKeyVaultTenantId,
                AzureAccessToken = azureKeyVaultAccessToken,
                AzureClientSecret = azureKeyVaultClientSecret,
                ManagedIdentity = azureKeyVaultManagedIdentity,
                AzureAuthority = azureAuthority
            };

            var configurationDiscoverer = new KeyVaultConfigurationDiscoverer();
            var materializedResult = await configurationDiscoverer.Materialize(configuration);
            AzureKeyVaultMaterializedConfiguration materialized;
            switch (materializedResult)
            {
                case ErrorOr<AzureKeyVaultMaterializedConfiguration>.Ok ok:
                    materialized = ok.Value;
                    break;
                default:
                    Console.Error.WriteLine("Failed to get configuration from Azure Key Vault.");
                    return 2;
            }

            const string RsaOid = "1.2.840.113549.1.1.1";
            if (materialized.PublicCertificate.GetKeyAlgorithm() is string alg and not RsaOid)
            {
                Console.Error.WriteLine("Certificate algorithm is not RSA.");
                return 2;
            }

            CryptographyClientOptions clientOptions = new()
            {
                Retry =
                    {
                        Delay = TimeSpan.FromSeconds(2),
                        MaxDelay = TimeSpan.FromSeconds(16),
                        MaxRetries = 5,
                        Mode = RetryMode.Exponential
                    }
            };

            var client = new CryptographyClient(materialized.KeyId, materialized.TokenCredential, clientOptions);

            using (var keyVault = await client.CreateRSAAsync())
            {
                return await PerformSignOnVsixAsync(
                    vsixFilePath,
                    force,
                    timestampServer,
                    fileDigestAlgorithm.Value,
                    timestampDigestAlgorithm.Value,
                    materialized.PublicCertificate,
                    keyVault
                );
            }
        }

        private static X509Certificate2 GetCertificateFromCertificateStore(string sha1)
        {
            using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
                var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, sha1, false);
                if (certificates.Count > 0)
                {
                    return certificates[0];
                }
            }
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
                var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, sha1, false);
                if (certificates.Count == 0)
                {
                    return null;
                }
                return certificates[0];
            }
        }

        private static AsymmetricAlgorithm GetSigningKeyFromCertificate(X509Certificate2 certificate)
        {
            const string RSA = "1.2.840.113549.1.1.1";
            const string Ecc = "1.2.840.10045.2.1";
            var keyAlgorithm = certificate.GetKeyAlgorithm();
            switch (keyAlgorithm)
            {
                case RSA:
                    return certificate.GetRSAPrivateKey();
                case Ecc:
                    return certificate.GetECDsaPrivateKey();
                default:
                    throw new InvalidOperationException("Unknown certificate signing algorithm.");
            }
        }

        private static async ValueTask<int> PerformSignOnVsixAsync
        (
            string vsixPath,
            bool force,
            Uri timestampUri,
            HashAlgorithmName fileDigestAlgorithm,
            HashAlgorithmName timestampDigestAlgorithm,
            X509Certificate2 certificate,
            AsymmetricAlgorithm signingKey
        )
        {
            using (var package = OpcPackage.Open(vsixPath, OpcPackageFileMode.ReadWrite))
            {
                if (package.GetSignatures().Any() && !force)
                {
                    Console.Error.WriteLine("The VSIX is already signed.");
                    return 2;
                }
                var signBuilder = package.CreateSignatureBuilder();
                signBuilder.EnqueueNamedPreset<VSIXSignatureBuilderPreset>();
                var signingConfiguration = new SignConfigurationSet
                (
                    fileDigestAlgorithm: fileDigestAlgorithm,
                    signatureDigestAlgorithm: fileDigestAlgorithm,
                    publicCertificate: certificate,
                    signingKey: signingKey
                );
                var signature = signBuilder.Sign(signingConfiguration);
                if (timestampUri != null)
                {
                    var timestampBuilder = signature.CreateTimestampBuilder();
                    var result = await timestampBuilder.SignAsync(timestampUri, timestampDigestAlgorithm);
                    if (result == TimestampResult.Failed)
                    {
                        Console.Error.WriteLine("The time stamp failed.");
                        return 2;
                    }
                }
                Console.Out.WriteLine("The signing operation is complete.");
                return 0;
            }
        }
    }
}
