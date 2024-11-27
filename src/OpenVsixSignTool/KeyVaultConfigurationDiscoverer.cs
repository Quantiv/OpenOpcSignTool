using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace OpenVsixSignTool
{
    internal class KeyVaultConfigurationDiscoverer
    {
        public async Task<ErrorOr<AzureKeyVaultMaterializedConfiguration>> Materialize(AzureKeyVaultSignConfigurationSet configuration)
        {
            TokenCredential credential;
            if (configuration.ManagedIdentity)
            {
                credential = new DefaultAzureCredential();
            }
            else if(!string.IsNullOrWhiteSpace(configuration.AzureAccessToken))
            {
                credential = new AccessTokenCredential(configuration.AzureAccessToken);
            }
            else
            {
                if (string.IsNullOrWhiteSpace(configuration.AzureAuthority))
                {
                    credential = new ClientSecretCredential(configuration.AzureTenantId, configuration.AzureClientId, configuration.AzureClientSecret);
                }
                else
                {
                    ClientSecretCredentialOptions options = new()
                    {
                        AuthorityHost = AuthorityHostNames.GetUriForAzureAuthorityIdentifier(configuration.AzureAuthority)
                    };
                    credential = new ClientSecretCredential(configuration.AzureTenantId, configuration.AzureClientId, configuration.AzureClientSecret, options);
                }
            }

            X509Certificate2 certificate;
            KeyVaultCertificate azureCertificate;
            try
            {
                var certClient = new CertificateClient(configuration.AzureKeyVaultUrl, credential);

                if (!string.IsNullOrWhiteSpace(configuration.AzureKeyVaultCertificateVersion))
                {
                    azureCertificate = (await certClient.GetCertificateVersionAsync(configuration.AzureKeyVaultCertificateName, configuration.AzureKeyVaultCertificateVersion).ConfigureAwait(false)).Value;
                }
                else
                {
                    azureCertificate = (await certClient.GetCertificateAsync(configuration.AzureKeyVaultCertificateName).ConfigureAwait(false)).Value;
                }

                certificate = new X509Certificate2(azureCertificate.Cer);
            }
            catch (Exception e)
            {
                return e;
            }
            var keyId = azureCertificate.KeyId;

            if (keyId is null)
            {
                return new InvalidOperationException("The Azure certificate does not have an associated private key.");
            }

            return new AzureKeyVaultMaterializedConfiguration(credential, certificate, keyId);
        }
    }
}
