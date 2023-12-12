# processes a pktmon ETL to txt, then parses the text with component list details
# requires the "pktmon list --json" output from the system where the pktmon was collected from

using namespace System.Collections.Generic

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]
    $EtlFile = $null,

    [Parameter(Mandatory=$true)]
    [string]
    $CompListFile = $null
)


function Convert-HexDump2Stream {
    [CmdletBinding()]
    param (
        [Parameter()]
        [List[string]]
        $hexDump
    )

    $stream = [List[string]]::new()

    foreach ( $l in $hexDump ) {
        # sample formatting
        # start with: 	0x0000:  7085 c286 c720 0015 5d01 be1e 0800 4500
        # end with  : 7085c286c72000155d01be1e08004500 
        #$tmp = ($l -Replace("\s+", '')).Split(':')[-1]
        if ($l -match "^\s+0x\d{4}:\s+(?<a>(\w{4}\s?)+)$") {
            $tmp = $matches.a -replace "\s+", ''
        } else {
            $tmp = ($l -Replace("\s+", '')).Split(':')[-1]
        }

        $stream.Add($tmp)
    }

    # returned the hex stream by joining all the parts
    return ($stream -join '')
}

#if ( [string]::IsNullOrEmpty ( $EtlFile ) )

try {
    $etlFileObj = Get-Item "$EtlFile" -EA Stop
} catch {
    return ( Write-Error "EtlFile was not found: $_" -EA Stop )
}

try {
    $compFileObj = Get-Item "$CompListFile" -EA Stop
} catch {
    return ( Write-Error "Component list file was not found: $_" -EA Stop )
}



# process the ETL
# ETL to PCAPNG file first
pktmon etl2pcap "$EtlFile"


# ETL to TXT
$txtFile = "$($etlFileObj.DirectoryName)\$($etlFileObj.BaseName).txt"
pktmon etl2txt "$EtlFile" --out "$txtFile" --hex

# flatten the pktmon component list
Push-Location $PSScriptRoot
$compList = .\Process-PktmonList.ps1 -ComponentListPath "$($compFileObj.FullName)"
Pop-Location


# create the parsed file and stream writer
$pTxtFile = "$($etlFileObj.DirectoryName)\$($etlFileObj.BaseName)-Parsed.log"
$null = New-Item "$pTxtFile" -ItemType File -Force
$stream = [System.IO.StreamWriter]::new($pTxtFile)

# loop through the text file and fill in component IDs
$count = 0
$matched = 0
$script:NewFile = [List[string]]::new()

$currHexStream = [List[string]]::new()

switch -Regex -CaseSensitive -File "$txtFile" {
    "^.*\[Microsoft-Windows-PktMon\].*$" {
        Write-Verbose $_

        if ($currHexStream.Count -gt 0) {
            $hexStream = Convert-HexDump2Stream $currHexStream
            $script:NewFile.Add("        Hex stream: $hexStream")

            $currHexStream.Clear()
            $count = $count + 1
        }

        $matched = $matched + 1

        # split the line by comma
        $csvLine = $_.split(',').Trim(' ')

        # find the component ID
        $compId = $csvLine | & { process {
            if ($_ -match 'Component ') {
                return [int]($_.Split(' ')[-1])
            }
        } }

        if ( -NOT $compId ) {
            Write-Warning "Could not parse the component ID. Skipping parsing."
            $script:NewFile.Add($_)
            continue
        }

        # match the ID to the flattend list ... there may be more than one :(
        $component = [List[object]]::new()
        $compList | & { process {
            if ($_.Id -eq $compId) {
                $component.Add( $_ )
            }
        } }

        if ($component.Count -lt 1) {
            # check for matches under SecondaryId before failing.
            $compList | & { process {
                if ($_.SecondaryId -eq $compId) {
                    $component.Add( $_ )
                }
            } }

            # now fail if nothing was found
            if ($component.Count -lt 1) {
                Write-Warning "Could not find a matching component. Skipping parsing."
                $script:NewFile.Add($_)
                continue
            }
        }

        # there is a component match at this point, now do something with it
        # for a single match simply add it...
        #echo "num comp: $($component.Count)"
        if ($component.Count -eq 1) {
            for ($i = 0; $i -lt $csvLine.Count; $i++) {
                #echo "matching: $($csvLine[$i])"
                if ($csvLine[$i] -match 'Component ') {
                    # echo "match found: $($csvLine[$i])"
                    $csvLine[$i] = " $($component.Group) [$($component.Name)] ($($csvLine[$i]))"
                }
            }

            #Write-Host -ForegroundColor green $csvLine
        # multiple component matches need some logic
        } elseif ($component.Count -gt 1) {
            # the Type determines which component to use
            # Type IP - match a component with L3/L4
            # Type Ethernet - match L2
            # anything else, use the base component
            $type = $csvLine | & { process {
                if ($_ -match "Type ") {
                    return ($_.Split(' ')[-1])
                }
            } }

            switch ($type) {
                "IP" {  
                    $compMatch = $component | Where-Object Name -match "L3"
                }

                "Ethernet" {  
                    $compMatch = $component | Where-Object Name -match "L2"
                }

                Default {
                    $compMatch = $component | Where-Object { $_.Name -notmatch "L2" -and $_.Name -notmatch "L3" }
                }
            }

            for ($i = 0; $i -lt $csvLine.Count; $i++) {
                #echo "matching: $($csvLine[$i])"
                if ($csvLine[$i] -match 'Component ') {
                    # echo "match found: $($csvLine[$i])"
                    $csvLine[$i] = " $($compMatch.Group) [$($compMatch.Name)] ($($csvLine[$i]))"
                }
            }

        }


        $script:NewFile.Add("$($csvLine -join ', ')")

        # write to file if necessary
        if ( $script:NewFile.Count -ge 10000 ) {
            # write to file
            foreach ( $i in $script:NewFile ) { $stream.WriteLine( $i ) }

            # clear the list
            $script:NewFile.Clear()
        }
    }

    # this converts hex to hex streams to make working with Wireshark easier
    "^\s+0x\d{4}:\s+(\w{4}\s?)+$" {
        # currently does not write the hex dump to file, only the hex stream, so just record the stream, don't increment anything
        $currHexStream.Add($_)
    }

    default {
        if ($currHexStream.Count -gt 0) {
            $hexStream = Convert-HexDump2Stream $currHexStream
            $script:NewFile.Add("        Hex stream: $hexStream")

            $currHexStream.Clear()
            $count = $count + 1
        }

        $count = $count + 1

        $script:NewFile.Add($_)

        if ( $script:NewFile.Count -ge 10000 ) {
            # write to file
            foreach ( $i in $script:NewFile ) { $stream.WriteLine( $i ) }

            # clear the list
            $script:NewFile.Clear()
        }
    }
}

# in case the file ends with hex data that needs to be converted and added
if ($currHexStream.Count -gt 0) {
    $hexStream = Convert-HexDump2Stream $currHexStream
    $script:NewFile.Add("        Hex stream: $hexStream")

    $currHexStream.Clear()
    $count = $count + 1
}

# write remaining lines to file
foreach ( $i in $script:NewFile ) { $stream.WriteLine( $i ) }

$stream.Close()
