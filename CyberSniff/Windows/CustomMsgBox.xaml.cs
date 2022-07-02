using System;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using CyberSniff.Models;
using MaterialDesignThemes.Wpf;

namespace CyberSniff.Windows
{
    public partial class CustomMsgBox : Window
    {
        private bool closeStoryBoardCompleted;

        public CustomMsgBox(MsgBox messageBoxObject)
        {
            InitializeComponent();
            if (Globals.Settings?.Background != null && Globals.Settings.Background != "None")
            {
                var _ = new BitmapImage();
                _.BeginInit();
                _.UriSource = new Uri(Globals.Settings.Background);
                _.EndInit();
            }

            MsgBoxIco.Kind = messageBoxObject.Icon switch
            {
                MsgBox.MsgBoxIcon.Error => PackIconKind.ErrorOutline,
                MsgBox.MsgBoxIcon.Information => PackIconKind.InformationOutline,
                MsgBox.MsgBoxIcon.Question => PackIconKind.QuestionMarkCircleOutline,
                MsgBox.MsgBoxIcon.Success => PackIconKind.Check,
                MsgBox.MsgBoxIcon.Warning => PackIconKind.WarningBoxOutline,
                _ => MsgBoxIco.Kind
            };

            switch (messageBoxObject.Button)
            {
                case MsgBox.MsgBoxBtn.Ok:
                    OkButton.Visibility = Visibility.Visible;
                    break;

                case MsgBox.MsgBoxBtn.OkCancel:
                    OkButton.Visibility = Visibility.Visible;
                    CancelButton.Visibility = Visibility.Visible;
                    break;

                case MsgBox.MsgBoxBtn.RetryCancel:
                    RetryBtn.Visibility = Visibility.Visible;
                    CancelButton.Visibility = Visibility.Visible;
                    break;

                case MsgBox.MsgBoxBtn.YesNo:
                    YesButton.Visibility = Visibility.Visible;
                    NoButton.Visibility = Visibility.Visible;
                    break;

                case MsgBox.MsgBoxBtn.YesNoCancel:
                    YesButton.Visibility = Visibility.Visible;
                    NoButton.Visibility = Visibility.Visible;
                    CancelButton.Visibility = Visibility.Visible;
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }

            MsgBoxContent.Text = messageBoxObject.Message;
        }

        public MsgBox.MsgBoxResult Result { get; private set; }

        private void HandleButtonClicks(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn)
                Result = btn.Name switch
                {
                    "OKBtn" => MsgBox.MsgBoxResult.Ok,
                    "YesBtn" => MsgBox.MsgBoxResult.Yes,
                    "NoBtn" => MsgBox.MsgBoxResult.No,
                    "CancelBtn" => MsgBox.MsgBoxResult.Cancel,
                    "RetryBtn" => MsgBox.MsgBoxResult.Retry,
                    _ => Result
                };

            Close();
        }

        private void Storyboard_Completed(object sender, EventArgs e)
        {
            closeStoryBoardCompleted = true;
            Close();
        }

        private void Window_Closing(object sender, CancelEventArgs e)
        {
            if (closeStoryBoardCompleted) return;
            
            var sb = FindResource("CloseAnim") as BeginStoryboard;
            sb?.Storyboard.Begin();
            e.Cancel = true;
        }
    }
}