﻿using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Microwalk.FrameworkBase.Utilities;

/// <summary>
/// Allows loading a MAP file and provides lookup functionality to query symbol names for given addresses.
/// </summary>
public class MapFile
{
    private readonly ILogger? _logger;

    /// <summary>
    /// Sorted symbol addresses, used for finding the nearest match of a given address.
    /// </summary>
    private readonly List<uint> _addresses = new();

    /// <summary>
    /// Maps symbol addresses to symbol names.
    /// </summary>
    public Dictionary<uint, string> SymbolNames { get; } = new();

    /// <summary>
    /// Returns the name of the associated image file.
    /// </summary>
    public string ImageName { get; private set; } = ""; // Will be initialized when loading the MAP file

    /// <summary>
    /// Creates a new empty MAP file object. Load a MAP file using the <see cref="InitializeFromFileAsync"/> method.
    /// </summary>
    /// <param name="logger">Logger instance. If none is given, logging is disabled.</param>
    public MapFile(ILogger? logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Parses the given MAP file. The file must have the following format:
    /// [image name]
    /// [hex start address 1] [symbol name 1]
    /// [hex start address 2] [symbol name 2]
    /// ...
    /// </summary>
    /// <param name="mapFileName">Path to the MAP file.</param>
    /// <returns></returns>
    public async Task InitializeFromFileAsync(string mapFileName)
    {
        // Read entire map file
        var mapFileLines = await File.ReadAllLinesAsync(mapFileName);

        // Read image name
        if(mapFileLines.Length < 1 || string.IsNullOrWhiteSpace(mapFileLines[0]))
        {
            if(_logger != null)
                await _logger.LogErrorAsync("Invalid MAP file. A MAP file has to contain the associated image name in the very first line.");
            throw new InvalidDataException("Invalid MAP file.");
        }

        ImageName = mapFileLines[0];

        // Parse entries
        var entryRegex = new Regex("^(?:0x)?([0-9a-fA-F]+)\\s+(.+)$", RegexOptions.Compiled);
        foreach(var line in mapFileLines.Skip(1))
        {
            // Ignore entry lines
            if(string.IsNullOrWhiteSpace(line))
                continue;

            // Parse entry
            var match = entryRegex.Match(line);
            if(!match.Success
               || match.Groups.Count != 3
               || !uint.TryParse(match.Groups[1].Value, NumberStyles.HexNumber, null, out uint entryAddress))
            {
                if(_logger != null)
                    await _logger.LogWarningAsync($"Ignoring unrecognized line in MAP file: {line}");
                continue;
            }

            string entrySymbolName = match.Groups[2].Value.TrimEnd();

            // Check whether address is already known
            if(SymbolNames.ContainsKey(entryAddress))
            {
                if(_logger != null)
                    await _logger.LogWarningAsync($"Ignoring duplicate MAP entry for address {entryAddress:x8}");
                continue;
            }

            // Store entry in lookup tables
            _addresses.Add(entryAddress);
            SymbolNames.Add(entryAddress, entrySymbolName);
        }

        // Sort address lookup, to allow binary search
        _addresses.Sort();
    }

    /// <summary>
    /// Finds the nearest smaller symbol to the given image address.
    /// </summary>
    /// <param name="address">Image relative address.</param>
    /// <returns>The symbol data corresponding to the given address, or null.</returns>
    public (uint StartAddress, string Name)? GetSymbolDataByAddress(uint address)
    {
        // Find address index in address array
        int index = _addresses.BinarySearch(address);
        if(index >= 0)
        {
            // Found, this is a symbol base address
            return (address, SymbolNames[address]);
        }

        // Not a base address, but BinarySearch yields the negated index of the next larger element
        index = ~index;
        if(index == 0)
        {
            // Not found
            return null;
        }

        // Get the index of the next smaller element
        --index;
        return (_addresses[index], SymbolNames[_addresses[index]]);
    }
}