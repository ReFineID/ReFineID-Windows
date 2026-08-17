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

    private readonly DispatcherQueue dispatcher;

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
            this.ShowSuccess($"Read the remote card of {holder}.");
        }
        catch (NativeRappException error)
        {
            this.ShowError(error.Message);
        }
        finally
        {
            this.SetBusy(false);
            NativeRappService.EndPairing(handle);
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

    private void ForgetIdentity()
    {
        this.HolderText.Text = string.Empty;
        this.HolderText.Visibility = Visibility.Collapsed;
        this.ForgetIdentityButton.Visibility = Visibility.Collapsed;
        this.ConnectRemoteReaderButton.Visibility = Visibility.Visible;

        // Clearing the row is not enough now that a pairing is durable: drop
        // the stored pair keys from the device-only credential too.
        try
        {
            NativeRappService.ForgetPairings();
            this.StatusInfoBar.IsOpen = false;
        }
        catch (NativeRappException error)
        {
            this.ShowError(error.Message);
        }
    }

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
