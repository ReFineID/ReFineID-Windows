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

using Microsoft.UI.Xaml;
using Windows.Graphics;

/// <summary>The single window: a Mica-backed title bar over the main page.</summary>
internal sealed partial class MainWindow : Window
{
    /// <summary>Default window size, tall enough to leave space below the list.</summary>
    private static readonly SizeInt32 InitialSize = new(760, 1040);

    public MainWindow()
    {
        this.InitializeComponent();
        this.ExtendsContentIntoTitleBar = true;
        this.SetTitleBar(this.AppTitleBar);
        this.AppWindow.SetIcon("Assets/AppIcon.ico");
        this.AppWindow.Resize(InitialSize);
        this.RootFrame.Navigate(typeof(MainPage));
    }
}
