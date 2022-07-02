using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CyberSniff.Classes
{
    /// <summary>
    ///     https://github.com/BrunoVT1992/ConsoleTable/blob/master/ConsoleTable/Table.cs
    /// </summary>
    public class TableHandler
    {
        private const string TopLeftJoint = "┌";

        private const string TopRightJoint = "┐";

        private const string BottomLeftJoint = "└";

        private const string BottomRightJoint = "┘";

        private const string TopJoint = "┬";

        private const string BottomJoint = "┴";

        private const string LeftJoint = "├";

        private const string MiddleJoint = "┼";

        private const string RightJoint = "┤";

        private const char HorizontalLine = '─';

        private const string VerticalLine = "│";

        private string[] headers;

        private readonly List<string[]> rows = new();

        private static int Padding => 1;

        private bool HeaderTextAlignRight { get; set; }

        private bool RowTextAlignRight { get; set; }

        public void SetHeaders(params string[] headers)
        {
            this.headers = headers;
        }

        public void AddRow(params string[] row)
        {
            rows.Add(row);
        }

        public void ClearRows()
        {
            rows.Clear();
        }

        private int[] GetMaxCellWidths(List<string[]> table)
        {
            var maximumColumns = table.Select(row => row.Length).Prepend(0).Max();

            var maximumCellWidths = new int[maximumColumns];
            for (var i = 0; i < maximumCellWidths.Length; i++)
                maximumCellWidths[i] = 0;

            var paddingCount = 0;
            if (Padding > 0)
                //Padding is left and right
                paddingCount = Padding * 2;

            foreach (var row in table)
                for (var i = 0; i < row.Length; i++)
                {
                    var maxWidth = row[i].Length + paddingCount;

                    if (maxWidth > maximumCellWidths[i])
                        maximumCellWidths[i] = maxWidth;
                }

            return maximumCellWidths;
        }

        private static StringBuilder CreateTopLine(IReadOnlyList<int> maximumCellWidths, int rowColumnCount,
            StringBuilder formattedTable)
        {
            for (var i = 0; i < rowColumnCount; i++)
                switch (i)
                {
                    case 0 when i == rowColumnCount - 1:
                        formattedTable.AppendLine(
                            $"{TopLeftJoint}{string.Empty.PadLeft(maximumCellWidths[i], HorizontalLine)}{TopRightJoint}");
                        break;
                    case 0:
                        formattedTable.Append(
                            $"{TopLeftJoint}{string.Empty.PadLeft(maximumCellWidths[i], HorizontalLine)}");
                        break;
                    default:
                    {
                        if (i == rowColumnCount - 1)
                            formattedTable.AppendLine(
                                $"{TopJoint}{string.Empty.PadLeft(maximumCellWidths[i], HorizontalLine)}{TopRightJoint}");
                        else
                            formattedTable.Append(
                                $"{TopJoint}{string.Empty.PadLeft(maximumCellWidths[i], HorizontalLine)}");
                        break;
                    }
                }

            return formattedTable;
        }

        private static StringBuilder CreateBottomLine(IReadOnlyList<int> maximumCellWidths, int rowColumnCount,
            StringBuilder formattedTable)
        {
            for (var i = 0; i < rowColumnCount; i++)
                switch (i)
                {
                    case 0 when i == rowColumnCount - 1:
                        formattedTable.AppendLine(
                            $"{BottomLeftJoint}{string.Empty.PadLeft(maximumCellWidths[i], HorizontalLine)}{BottomRightJoint}");
                        break;
                    case 0:
                        formattedTable.Append(
                            $"{BottomLeftJoint}{string.Empty.PadLeft(maximumCellWidths[i], HorizontalLine)}");
                        break;
                    default:
                    {
                        if (i == rowColumnCount - 1)
                            formattedTable.AppendLine(
                                $"{BottomJoint}{string.Empty.PadLeft(maximumCellWidths[i], HorizontalLine)}{BottomRightJoint}");
                        else
                            formattedTable.Append(
                                $"{BottomJoint}{string.Empty.PadLeft(maximumCellWidths[i], HorizontalLine)}");
                        break;
                    }
                }

            return formattedTable;
        }

        private StringBuilder CreateValueLine(IReadOnlyList<int> maximumCellWidths, IReadOnlyCollection<string> row,
            bool alignRight,
            StringBuilder formattedTable)
        {
            var cellIndex = 0;
            var lastCellIndex = row.Count - 1;

            var paddingString = string.Empty;
            if (Padding > 0)
                paddingString = string.Concat(Enumerable.Repeat(' ', Padding));

            foreach (var column in row)
            {
                var restWidth = maximumCellWidths[cellIndex];
                if (Padding > 0)
                    restWidth -= Padding * 2;

                var cellValue = alignRight ? column.PadLeft(restWidth, ' ') : column.PadRight(restWidth, ' ');

                switch (cellIndex)
                {
                    case 0 when cellIndex == lastCellIndex:
                        formattedTable.AppendLine(
                            $"{VerticalLine}{paddingString}{cellValue}{paddingString}{VerticalLine}");
                        break;
                    case 0:
                        formattedTable.Append($"{VerticalLine}{paddingString}{cellValue}{paddingString}");
                        break;
                    default:
                    {
                        if (cellIndex == lastCellIndex)
                            formattedTable.AppendLine(
                                $"{VerticalLine}{paddingString}{cellValue}{paddingString}{VerticalLine}");
                        else
                            formattedTable.Append($"{VerticalLine}{paddingString}{cellValue}{paddingString}");
                        break;
                    }
                }

                cellIndex++;
            }

            return formattedTable;
        }

        private static StringBuilder CreateSeparatorLine(IReadOnlyList<int> maximumCellWidths, int previousRowColumnCount,
            int rowColumnCount, StringBuilder formattedTable)
        {
            var maximumCells = Math.Max(previousRowColumnCount, rowColumnCount);

            for (var i = 0; i < maximumCells; i++)
                switch (i)
                {
                    case 0 when i == maximumCells - 1:
                        formattedTable.AppendLine(
                            $"{LeftJoint}{string.Empty.PadLeft(maximumCellWidths[i], HorizontalLine)}{RightJoint}");
                        break;
                    case 0:
                        formattedTable.Append(
                            $"{LeftJoint}{string.Empty.PadLeft(maximumCellWidths[i], HorizontalLine)}");
                        break;
                    default:
                    {
                        if (i == maximumCells - 1)
                        {
                            if (i > previousRowColumnCount)
                                formattedTable.AppendLine(
                                    $"{TopJoint}{string.Empty.PadLeft(maximumCellWidths[i], HorizontalLine)}{TopRightJoint}");
                            else if (i > rowColumnCount)
                                formattedTable.AppendLine(
                                    $"{BottomJoint}{string.Empty.PadLeft(maximumCellWidths[i], HorizontalLine)}{BottomRightJoint}");
                            else if (i > previousRowColumnCount - 1)
                                formattedTable.AppendLine(
                                    $"{MiddleJoint}{string.Empty.PadLeft(maximumCellWidths[i], HorizontalLine)}{TopRightJoint}");
                            else if (i > rowColumnCount - 1)
                                formattedTable.AppendLine(
                                    $"{MiddleJoint}{string.Empty.PadLeft(maximumCellWidths[i], HorizontalLine)}{BottomRightJoint}");
                            else
                                formattedTable.AppendLine(
                                    $"{MiddleJoint}{string.Empty.PadLeft(maximumCellWidths[i], HorizontalLine)}{RightJoint}");
                        }
                        else
                        {
                            if (i > previousRowColumnCount)
                                formattedTable.Append(
                                    $"{TopJoint}{string.Empty.PadLeft(maximumCellWidths[i], HorizontalLine)}");
                            else if (i > rowColumnCount)
                                formattedTable.Append(
                                    $"{BottomJoint}{string.Empty.PadLeft(maximumCellWidths[i], HorizontalLine)}");
                            else
                                formattedTable.Append(
                                    $"{MiddleJoint}{string.Empty.PadLeft(maximumCellWidths[i], HorizontalLine)}");
                        }

                        break;
                    }
                }

            return formattedTable;
        }

        public override string ToString()
        {
            var table = new List<string[]>();

            var firstRowIsHeader = false;
            if (headers?.Any() == true)
            {
                table.Add(headers);
                firstRowIsHeader = true;
            }

            if (rows?.Any() == true)
                table.AddRange(rows);

            if (!table.Any())
                return string.Empty;

            var formattedTable = new StringBuilder();

            var previousRow = table.FirstOrDefault();
            var nextRow = table.FirstOrDefault();

            var maximumCellWidths = GetMaxCellWidths(table);

            formattedTable = CreateTopLine(maximumCellWidths, nextRow.Length, formattedTable);

            var rowIndex = 0;
            var lastRowIndex = table.Count - 1;

            for (var i = 0; i < table.Count; i++)
            {
                var row = table[i];

                var align = RowTextAlignRight;
                if (i == 0 && firstRowIsHeader)
                    align = HeaderTextAlignRight;

                formattedTable = CreateValueLine(maximumCellWidths, row, align, formattedTable);

                previousRow = row;

                if (rowIndex != lastRowIndex)
                {
                    nextRow = table[rowIndex + 1];
                    formattedTable = CreateSeparatorLine(maximumCellWidths, previousRow.Length, nextRow.Length,
                        formattedTable);
                }

                rowIndex++;
            }

            if (previousRow != null)
                formattedTable = CreateBottomLine(maximumCellWidths, previousRow.Length, formattedTable);

            return formattedTable.ToString();
        }
    }
}