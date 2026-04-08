using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Aivpn.Ui.ViewModels;
using Aivpn.Ui.Views;
using Aivpn.Ui.Services;

namespace Aivpn.Ui;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.MainWindow = new MainWindow
            {
                DataContext = new MainWindowViewModel(ClientServiceFactory.Create()),
            };
        }

        base.OnFrameworkInitializationCompleted();
    }
}
