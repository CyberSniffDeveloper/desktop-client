using CyberSniff.Models;
using System.ComponentModel;
using System.Threading.Tasks;

namespace CyberSniff.Interfaces
{
    public interface IExportDrawer
    {
        Task DrawTableForExport(BindingList<CaptureGrid> submittedDataTable, string submittedFilePath);
    }
}