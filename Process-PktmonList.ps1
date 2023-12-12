# flatten pktmon component list
# us a file, when present, otherwise use the local system

using namespace System.Collections.Generic

[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $ComponentListPath = $null
)

# get the component list
if ( [string]::IsNullOrEmpty( $ComponentListPath ) ) {
    # read the load list
    [List[Object]]$compList = pktmon list --json | ConvertFrom-Json -Depth 10
} else {
    # get the list from file
    [List[Object]]$compList = Get-Content "$ComponentListPath" | ConvertFrom-Json -Depth 10
}

# fail if the list is empty
if ( $compList.Count -lt 1 ) {
    return ( Write-Error "The pktmon component list is empty." -EA Stop )
}

# flatten the list into something easier to manage
$mainCompList = [List[Object]]::new()

# process each group
foreach ( $group in $compList ) {
    # process each component in the group
    foreach ( $comp in $group.Components ) {
        # contains the flattend component record
        $tmpObj = [PSCustomObject] @{
            Group = $group.Group
        }

        # list of component names
        $compProps = $comp | Get-Member -Type NoteProperty | ForEach-Object Name

        # loop through each component property
        foreach ($prop in $compProps) {
            # the component object
            $obj = $comp."$prop"

            # process the property with some special exceptions
            switch ($prop) {
                "Properties" {
                    # flatten properies
                    foreach ($o in $obj) {
                        # does the property already exist in tmpObj?
                        $np = $tmpObj | Get-Member -Type NoteProperty | ForEach-Object Name
                
                        if ( $o.Name -in $np ) {
                            # combine with the existing note property
                            if ( $tmpObj."$($o.Name)" -is [array]) {
                                $tmpObj."$($o.Name)" += $o.Value
                            } else {
                                $tmpArr = @()
                                $tmpArr += $tmpObj."$($o.Name)"
                                $tmpArr += $o.Value
                
                                # add the new array to the object
                                $tmpObj."$($o.Name)" = $tmpArr
                            }  
                        } else {
                            # add the new note property
                            $tmpObj | Add-Member -MemberType NoteProperty -Name $o.Name -Value $o.Value
                        }
                    }
                }

                "Counters" {
                    # flatten counters
                    $tmpObj | Add-Member -MemberType NoteProperty -Name $prop -Value $obj.Name
                }

                default {
                    # no other component property is an array, so just add it to the PS object
                    $tmpObj | Add-Member -MemberType NoteProperty -Name $prop -Value $obj
                }
            }
        }

        # add the tmpObj to the main list
        $mainCompList.Add($tmpObj)

        # cleanup
        Remove-Variable tmpObj, tmpArr, np, obj, compProps -EA SilentlyContinue
    }
}

return $mainCompList