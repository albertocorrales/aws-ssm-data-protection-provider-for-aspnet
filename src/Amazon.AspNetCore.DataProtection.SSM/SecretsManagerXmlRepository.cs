/*
Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.

  Licensed under the Apache License, Version 2.0 (the "License").
  You may not use this file except in compliance with the License.
  A copy of the License is located at

      http://www.apache.org/licenses/LICENSE-2.0

  or in the "license" file accompanying this file. This file is distributed
  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
  express or implied. See the License for the specific language governing
  permissions and limitations under the License.
 */
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace Amazon.AspNetCore.DataProtection.SSM
{
    /// <summary>
    /// Implementation of IXmlRepository that handles storing and retrieving DataProtection keys from the SSM Parameter Store. 
    /// </summary>
    internal class SecretsManagerXmlRepository : IXmlRepository, IDisposable
    {
        const string TagDataProtectionKey = "DataProtectionKey";

        private readonly IAmazonSecretsManager _secretsManagerClient;
        private readonly string _secretNamePrefix;
        private readonly PersistOptions _options;
        private readonly ILogger<SSMXmlRepository> _logger;

        /// <summary>
        /// Create an SSMXmlRepository
        /// 
        /// This class is internal and the constructor isn't meant to be called outside this assembly.
        /// It's used by the IDataProtectionBuilder.PersistKeysToAWSSystemsManager extension method.
        /// </summary>
        /// <param name="secretsManagerClient"></param>
        /// <param name="secretNamePrefix"></param>
        /// <param name="options"></param>
        /// <param name="loggerFactory"></param>
        public SecretsManagerXmlRepository(IAmazonSecretsManager secretsManagerClient, string secretNamePrefix, PersistOptions options = null, ILoggerFactory loggerFactory = null)
        {
            _secretsManagerClient = secretsManagerClient ?? throw new ArgumentNullException(nameof(secretsManagerClient));
            _secretNamePrefix = secretNamePrefix ?? throw new ArgumentNullException(nameof(secretNamePrefix));
            _options = options ?? new PersistOptions();

            if (loggerFactory != null)
            {
                _logger = loggerFactory?.CreateLogger<SSMXmlRepository>();
            }
            else
            {
                _logger = NullLoggerFactory.Instance.CreateLogger<SSMXmlRepository>();
            }

            _logger.LogInformation($"Using SSM Parameter Store to persist DataProtection keys with parameter name prefix {_secretNamePrefix}");
        }



        /// <summary>
        /// Get all of the DataProtection keys from parameter store. Any parameter values that can't be parsed 
        /// as XML, the format of DataProtection keys, will not be returned.
        /// </summary>
        /// <returns></returns>
        public IReadOnlyCollection<XElement> GetAllElements()
        {
            return Task.Run(GetAllElementsAsync).GetAwaiter().GetResult();
        }

        private async Task<IReadOnlyCollection<XElement>> GetAllElementsAsync()
        {
            var request = new ListSecretsRequest
            {
                Filters = new List<Filter> 
                {
                    new Filter()
                    {
                        Key = FilterNameStringType.TagKey,
                        Values = new List<string> { TagDataProtectionKey }
                    }
                },
            };
            ListSecretsResponse response = null;

            var results = new List<XElement>();
            do
            {
                request.NextToken = response?.NextToken;
                try
                {
                    response = await _secretsManagerClient.ListSecretsAsync(request).ConfigureAwait(false);
                }
                catch (Exception e)
                {
                    _logger.LogError($"Error calling SSM to get parameters starting with {_secretNamePrefix}: {e.Message}");
                    throw;
                }

                foreach (var secret in response.SecretList)
                {
                    try
                    {
                        var GetSecretValueRequest = new GetSecretValueRequest
                        {
                            SecretId = secret.Name
                        };
                        var secretValueResponse = await _secretsManagerClient.GetSecretValueAsync(GetSecretValueRequest).ConfigureAwait(false);

                        var xml = XElement.Parse(secretValueResponse.SecretString);
                        results.Add(xml);
                    }
                    catch (Exception e)
                    {
                        _logger.LogError($"Error parsing key {secret.Name}, key will be skipped: {e.Message}");
                    }
                }

            } while (!string.IsNullOrEmpty(response.NextToken));

            _logger.LogInformation($"Loaded {results.Count} DataProtection keys");
            return results;
        }

        /// <summary>
        /// Stores the DataProtection key as parameter in SSM's parameter store. The parameter type will be set to SecureString.
        /// </summary>
        /// <param name="element"></param>
        /// <param name="friendlyName"></param>
        public void StoreElement(XElement element, string friendlyName)
        {
            Task.Run(() => StoreElementAsync(element, friendlyName)).Wait();
        }

        private async Task StoreElementAsync(XElement element, string friendlyName)
        {
            var secretName = _secretNamePrefix +
                            (friendlyName ??
                            element.Attribute("id")?.Value ??
                            Guid.NewGuid().ToString());

            var elementValue = element.ToString();
            
            try
            {
                var request = new CreateSecretRequest
                {
                    Name = secretName,
                    SecretString = elementValue,
                    Tags = new List<Tag> { new Tag { Key = TagDataProtectionKey } }
                };

                if (!string.IsNullOrEmpty(_options.KMSKeyId)) 
                {
                    request.KmsKeyId = _options.KMSKeyId;
                }

                if (!string.IsNullOrEmpty(_options.ReplicationRegion)) 
                {
                    request.AddReplicaRegions = new List<ReplicaRegionType> { new ReplicaRegionType() { Region = _options.ReplicationRegion } }
                }

                await _secretsManagerClient.CreateSecretAsync(request).ConfigureAwait(false);

                _logger.LogInformation($"Saved DataProtection key to SSM Parameter Store with parameter name {secretName}");
            }
            catch (Exception e)
            {
                _logger.LogError($"Error saving DataProtection key to SSM Parameter Store with parameter name {secretName}: {e.Message}");
                throw;
            }
        }

        #region IDisposable Support
        private bool disposedValue = false;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    _secretsManagerClient?.Dispose();
                }

                disposedValue = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }
        #endregion
    }
}
