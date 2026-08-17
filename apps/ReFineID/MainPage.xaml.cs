// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

namespace ReFineID;

using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

/// <summary>
/// The requester main screen: Document, Card, and Identity, mirroring the
/// mobile app. Remote Card and Connect Remote Reader drive the RAPP pairing
/// ceremony and a public card read; no credential is ever handled here.
/// </summary>
[SuppressMessage(
    "Performance",
    "CA1812:Avoid uninstantiated internal classes",
    Justification = "Instantiated by the root Frame through XAML type activation."
)]
internal sealed partial class MainPage : Page
{
    /// <summary>The TCP port the requester listens on for the phone's dial.</summary>
    private const int ListenPort = 47110;

    /// <summary>Requester label the phone shows during pairing.</summary>
    private const string RequesterName = "ReFineID Windows";

    /// <summary>Pairing-state poll cadence.</summary>
    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(700);

    /// <summary>Liveness cadence for a live pairing after the read.</summary>
    private static readonly TimeSpan LivenessInterval = TimeSpan.FromSeconds(7);

    private readonly DispatcherQueue dispatcher;

    /// <summary>The live pairing shown on the Person row, if any.</summary>
    private ulong? activeHandle;

    private DispatcherQueueTimer? livenessTimer;
    private bool livenessCheckRunning;

    public MainPage()
    {
        this.InitializeComponent();
        this.dispatcher = DispatcherQueue.GetForCurrentThread();
        this.DiagnosticsText.Text = DiagnosticsLabel();
#if DEBUG
        this.Loaded += this.OnLoaded;
#endif
    }

#if DEBUG
    /// <summary>Debug-only launch flag that opens the pairing QR on launch.</summary>
    private const string AutoPairArgument = "--pair";

    /// <summary>
    /// Debug-only convenience: <c>--pair</c> opens the pairing QR as soon as
    /// the window is ready, so a test rig shows it without a click. This is
    /// never compiled into a release build.
    /// </summary>
    private async void OnLoaded(object sender, RoutedEventArgs args)
    {
        this.Loaded -= this.OnLoaded;
        if (
            Array.Exists(Environment.GetCommandLineArgs(), argument => argument == AutoPairArgument)
        )
        {
            await this.RunRemoteCardAsync().ConfigureAwait(true);
        }
    }
#endif

    private static string DiagnosticsLabel()
    {
        Version? version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
        return version is null
            ? "ReFineID"
            : $"ReFineID {version.Major}.{version.Minor}.{version.Build}.{version.Revision}";
    }

    private async void RemoteCard_Click(object sender, RoutedEventArgs args) =>
        await this.RunRemoteCardAsync().ConfigureAwait(true);

    private async void ConnectRemoteReader_Click(object sender, RoutedEventArgs args) =>
        await this.RunRemoteCardAsync().ConfigureAwait(true);

    private async Task RunRemoteCardAsync()
    {
        // One pairing at a time: starting a new ceremony ends any live one.
        if (this.activeHandle is not null)
        {
            this.DropLivePairing(notice: null);
        }

        string? advertise = LocalAdvertiseEndpoint();
        if (advertise is null)
        {
            this.ShowError("No local network address was found to advertise to the phone.");
            return;
        }

        BeginPairingResult begun;
        try
        {
            begun = await Task.Run(() =>
                    NativeRappService.BeginPairing(
                        $"0.0.0.0:{ListenPort}",
                        advertise,
                        RequesterName
                    )
                )
                .ConfigureAwait(true);
        }
        catch (NativeRappException error)
        {
            this.ShowError(error.Message);
            return;
        }

        var dialog = new PairingDialog(begun.Handle, begun.OfferUri, this.dispatcher, PollInterval)
        {
            XamlRoot = this.XamlRoot,
        };
        _ = await dialog.ShowAsync();

        if (dialog.PairedHandle is ulong pairedHandle)
        {
            await this.ReadPairedCardAsync(pairedHandle).ConfigureAwait(true);
        }
        else if (dialog.Failure is string failure)
        {
            this.ShowError(failure);
        }
    }

    private async Task ReadPairedCardAsync(ulong handle)
    {
        this.SetBusy(true);
        try
        {
            CardReading reading = await Task.Run(() => NativeRappService.ReadCard(handle))
                .ConfigureAwait(true);
            string holder = string.IsNullOrWhiteSpace(reading.Identity.PersonId)
                ? reading.Identity.DisplayName
                : $"{reading.Identity.DisplayName} {reading.Identity.PersonId}";
            this.HolderText.Text = holder;
            this.HolderText.Visibility = Visibility.Visible;
            this.ForgetIdentityButton.Visibility = Visibility.Visible;
            this.ConnectRemoteReaderButton.Visibility = Visibility.Collapsed;

            // The pairing is the live connection and stays up behind the
            // identity: keep the handle and watch it, so the row clears the
            // moment the phone side goes away.
            this.activeHandle = handle;
            this.StartLivenessWatch();
            this.ShowSuccess($"Read the remote card of {holder}.");
        }
        catch (NativeRappException error)
        {
            this.ShowError(error.Message);
            NativeRappService.EndPairing(handle);
            return;
        }
        finally
        {
            this.SetBusy(false);
        }

        // Publish the card so Windows apps can use it while the pairing is live.
        // This caches the certificate over one more phone approval; a failure
        // leaves the identity shown, only not offered to Windows.
        try
        {
            await Task.Run(() => NativeRappService.PublishCard(handle)).ConfigureAwait(true);
        }
        catch (NativeRappException error)
        {
            this.ShowError(error.Message);
        }
    }

    private void StartLivenessWatch()
    {
        this.livenessTimer ??= this.dispatcher.CreateTimer();
        this.livenessTimer.Interval = LivenessInterval;
        this.livenessTimer.Tick += this.OnLivenessTick;
        this.livenessTimer.Start();
    }

    private async void OnLivenessTick(DispatcherQueueTimer sender, object args)
    {
        if (this.livenessCheckRunning || this.activeHandle is not ulong handle)
        {
            return;
        }

        this.livenessCheckRunning = true;
        try
        {
            await Task.Run(() => NativeRappService.CheckPairing(handle)).ConfigureAwait(true);
        }
        catch (NativeRappException)
        {
            this.DropLivePairing("The pairing ended; the phone closed or stopped answering.");
        }
        finally
        {
            this.livenessCheckRunning = false;
        }
    }

    private void DropLivePairing(string? notice)
    {
        if (this.livenessTimer is DispatcherQueueTimer timer)
        {
            timer.Stop();
            timer.Tick -= this.OnLivenessTick;
        }

        if (this.activeHandle is ulong handle)
        {
            this.activeHandle = null;
            // Stop publishing before the pairing ends; the pipe service is torn
            // down either way, but this closes it cleanly first.
            try
            {
                NativeRappService.UnpublishCard(handle);
            }
            catch (NativeRappException)
            {
                // The pairing may already be gone; ending the handle is enough.
            }
            NativeRappService.EndPairing(handle);
        }

        this.HolderText.Text = string.Empty;
        this.HolderText.Visibility = Visibility.Collapsed;
        this.ForgetIdentityButton.Visibility = Visibility.Collapsed;
        this.ConnectRemoteReaderButton.Visibility = Visibility.Visible;
        if (notice is string message)
        {
            this.ShowStatus(InfoBarSeverity.Informational, message);
        }
        else
        {
            this.StatusInfoBar.IsOpen = false;
        }
    }

    private async void ForgetIdentity_Click(object sender, RoutedEventArgs args) =>
        await this.ConfirmForgetIdentityAsync().ConfigureAwait(true);

    private async Task ConfirmForgetIdentityAsync()
    {
        // The scan was the consent to read; forgetting is destructive to the
        // device-local identity, so it takes its own explicit confirmation.
        // Cancel is the safe default the way Windows dialogs expect.
        var dialog = new ContentDialog
        {
            XamlRoot = this.XamlRoot,
            Title = "Forget identity?",
            Content = string.IsNullOrWhiteSpace(this.HolderText.Text)
                ? "The remote card will be removed from this device."
                : $"The remote card of {this.HolderText.Text} will be removed from this device.",
            PrimaryButtonText = "Forget",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
        };

        if (await dialog.ShowAsync() == ContentDialogResult.Primary)
        {
            this.ForgetIdentity();
        }
    }

    private void ForgetIdentity() =>
        // Ending the handle sends the clean close, so the phone drops its
        // side of the pairing at the same moment the row clears here.
        this.DropLivePairing(notice: null);

    private static string? LocalAdvertiseEndpoint()
    {
        foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (
                adapter.OperationalStatus != OperationalStatus.Up
                || adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback
            )
            {
                continue;
            }

            foreach (
                UnicastIPAddressInformation address in adapter.GetIPProperties().UnicastAddresses
            )
            {
                if (
                    address.Address.AddressFamily == AddressFamily.InterNetwork
                    && !IPAddress.IsLoopback(address.Address)
                )
                {
                    return string.Create(
                        CultureInfo.InvariantCulture,
                        $"{address.Address}:{ListenPort}"
                    );
                }
            }
        }

        return null;
    }

    private void SetBusy(bool busy)
    {
        this.BusyOverlay.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        this.BusyOverlay.IsHitTestVisible = busy;
    }

    private void ShowSuccess(string message) => this.ShowStatus(InfoBarSeverity.Success, message);

    private void ShowError(string message) => this.ShowStatus(InfoBarSeverity.Error, message);

    private void ShowStatus(InfoBarSeverity severity, string message)
    {
        this.StatusInfoBar.Severity = severity;
        this.StatusInfoBar.Message = message;
        this.StatusInfoBar.IsOpen = true;
    }
}
