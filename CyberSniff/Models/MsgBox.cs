namespace CyberSniff.Models
{
    public struct MsgBox
    {
        public enum MsgBoxBtn
        {
            YesNo,

            YesNoCancel,

            Ok,

            OkCancel,

            RetryCancel
        }

        public enum MsgBoxIcon
        {
            Error,

            Warning,

            Information,

            Question,

            Success
        }

        public enum MsgBoxResult
        {
            Yes,

            No,

            Cancel,

            Ok,

            Retry
        }

        public MsgBoxBtn Button { set; get; }

        public MsgBoxIcon Icon { set; get; }

        public string Message { set; get; }
    }
}