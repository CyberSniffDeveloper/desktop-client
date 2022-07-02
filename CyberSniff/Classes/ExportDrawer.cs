using CyberSniff.Interfaces;
using CyberSniff.Models;
using System;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;

namespace CyberSniff.Classes
{
    public class ExportDrawer : IExportDrawer
    {
        public async Task DrawTableForExport(BindingList<CaptureGrid> submittedDataTable, string submittedFilePath)
        {
            var table = new TableHandler();

            table.SetHeaders("IP address", "Port", "Country", "City", "State", "ISP");

            foreach (var row in submittedDataTable)
            {
                table.AddRow(row.IpAddress.ToString(), row.Port.ToString(), row.Country, row.City, row.State, row.Isp);
            }

            await File.WriteAllTextAsync(submittedFilePath, $"CyberSniff-OSS [version {Assembly.GetExecutingAssembly().GetCyberSniffVersionString()} RELEASE OSS] capture results, exported at {DateTime.UtcNow} UTC\nTotal items: {submittedDataTable.Count}\n\n");
            await File.AppendAllTextAsync(submittedFilePath, table.ToString());
        }
    }
}