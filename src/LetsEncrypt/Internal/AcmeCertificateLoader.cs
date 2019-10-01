// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

#if NETSTANDARD2_0
using IHostEnvironment = Microsoft.Extensions.Hosting.IHostingEnvironment;
#endif

namespace McMaster.AspNetCore.LetsEncrypt.Internal
{
    /// <summary>
    /// Loads certificates for all configured hostnames
    /// </summary>
    internal class AcmeCertificateLoader : IHostedService
    {
        private readonly CertificateSelector _selector;
        private readonly IHttpChallengeResponseStore _challengeStore;
        private readonly ICertificateStore _certificateStore;
        private readonly IOptions<LetsEncryptOptions> _options;
        private readonly ILogger<AcmeCertificateLoader> _logger;

        private readonly IHostEnvironment _hostEnvironment;
        private readonly IServer _server;
        private readonly IConfiguration _config;
        private volatile bool _hasRegistered;
        private CancellationTokenSource? _cts;

        public AcmeCertificateLoader(
            CertificateSelector selector,
            IHttpChallengeResponseStore challengeStore,
            ICertificateStore certificateStore,
            IOptions<LetsEncryptOptions> options,
            ILogger<AcmeCertificateLoader> logger,
            IHostEnvironment hostEnvironment,
            IServer server,
            IConfiguration config)
        {
            _selector = selector;
            _challengeStore = challengeStore;
            _certificateStore = certificateStore;
            _options = options;
            _logger = logger;
            _hostEnvironment = hostEnvironment;
            _server = server;
            _config = config;
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            if (_cts != null)
            {
                _cts.Cancel();
            }
            return Task.CompletedTask;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            if (!(_server is KestrelServer))
            {
                var serverType = _server.GetType().FullName;
                _logger.LogWarning("LetsEncrypt can only be used with Kestrel and is not supported on {serverType} servers. Skipping certificate provisioning.", serverType);
                return Task.CompletedTask;
            }

            if (_config.GetValue<bool>("UseIISIntegration"))
            {
                _logger.LogWarning("LetsEncrypt does not work with apps hosting in IIS. IIS does not allow for dynamic HTTPS certificate binding, " +
                    "so if you want to use Let's Encrypt, you'll need to use a different tool to do so.");
                return Task.CompletedTask;
            }

            // load certificates in the background

            if (!LetsEncryptDomainNamesWereConfigured())
            {
                _logger.LogInformation("No domain names were configured for Let's Encrypt");
                return Task.CompletedTask;
            }

            _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            Task.Factory.StartNew<Task>(async () =>
            {
                const string ErrorMessage = "Failed to create certificate";
                var retries = 5;
                var renewCert = false;

                while (!_cts.IsCancellationRequested && retries > 0)
                {
                    var renewDelay = TimeSpan.FromSeconds(30); // in the event of error, set initial retry to run soon
                    var now = DateTime.Now;
                    var success = true;
                    try
                    {
                        var cert = await LoadCert(renewCert, cancellationToken);

                        var expirationBuffer = TimeSpan.FromDays(_options.Value.DaysBeforeExpirationToRenew);
                        var expirationDate = cert.NotAfter;
                        renewDelay = expirationDate - now - expirationBuffer;
                    }
                    catch (AggregateException ex) when (ex.InnerException != null)
                    {
                        _logger.LogError(0, ex.InnerException, ErrorMessage);
                        success = false;

                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(0, ex, ErrorMessage);
                        success = false;
                    }

                    if (_cts.IsCancellationRequested)
                    {
                        return;
                    }


                    if (!success)
                    {
                        retries--;
                        _logger.LogInformation("Failed to create Let's Encrypt certificate. Will retry {retries} more times.", retries);
                        renewDelay = TimeSpan.FromTicks(renewDelay.Ticks * 2);
                    }

                    try
                    {
                        renewCert = true;
                        var renewOn = now + renewDelay;
                        _logger.LogInformation("Setting delayed task to renew Let's Encrypt certificate at {renewDateTime}", renewOn);
                        await Task.Delay(renewDelay, _cts.Token);
                    }
                    catch (TaskCanceledException)
                    {
                        _logger.LogInformation("Let's Encrypt certificate renewal canceled.");
                        return;
                    }

                }
            }, TaskCreationOptions.LongRunning | TaskCreationOptions.RunContinuationsAsynchronously);

            return Task.CompletedTask;
        }

        private bool LetsEncryptDomainNamesWereConfigured()
        {
            return _options.Value.DomainNames
                .Where(w => !string.Equals("localhost", w, StringComparison.OrdinalIgnoreCase))
                .Any();
        }

        private async Task<X509Certificate2> LoadCert(bool renew, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var options = _options.Value;
            var primaryDomainName = options.DomainNames[0];

            if (!renew)
            {
                var existingCert = _certificateStore.GetCertificate(primaryDomainName);
                if (existingCert != null)
                {
                    _logger.LogDebug("Certificate for {domainName} already found.", primaryDomainName);
                    return existingCert;
                }
            }

            using var factory = new CertificateFactory(options, _challengeStore, _logger, _hostEnvironment);
            var cert = await CreateCertificate(primaryDomainName, factory, cancellationToken);
            foreach (var domainName in options.DomainNames)
            {
                _selector.Use(domainName, cert);
            }

            return cert;
        }

        private async Task<X509Certificate2> CreateCertificate(string domainName, CertificateFactory factory, CancellationToken cancellationToken)
        {
            if (!_hasRegistered)
            {
                _hasRegistered = true;
                await factory.RegisterUserAsync(cancellationToken);
            }

            try
            {
                _logger.LogInformation("Creating certificate for {hostname} using ACME server {acmeServer}", domainName, _options.Value.GetAcmeServer(_hostEnvironment));
                var cert = await factory.CreateCertificateAsync(cancellationToken);
                _logger.LogInformation("Created certificate {subjectName} ({thumbprint})", cert.Subject, cert.Thumbprint);
                _certificateStore.Save(domainName, cert);
                return cert;
            }
            catch (Exception ex)
            {
                _logger.LogError(0, ex, "Failed to automatically create a certificate for {hostname}", domainName);
                throw;
            }
        }
    }
}
