#!powershell
# Alex Hrdy 2021
# Changes the state of one non-C disk on a Nutanix AHV VM

#Requires -Module Ansible.ModuleUtils.Legacy
#Requires -Module Ansible.ModuleUtils.SID

$TLS12Protocol = [System.Net.SecurityProtocolType] 'Ssl3 , Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $TLS12Protocol

$ErrorActionPreference = "Stop"

function Get-NutanixVMInfo {
<#
.SYNOPSIS
Return all information on a Nutanix VM specified by UUID from the Prism Element V2 API
.NOTES
Returns a custom object with the VM basic stats and info.
Requires a VM UUID, username, password, and cluster name.
#>
param(
 [ValidatePattern("[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}")]
 [String][Parameter(Mandatory=$True, Position=1)] $uuid,
 [String][Parameter(Mandatory=$True, Position=2)] $username,
 [String][Parameter(Mandatory=$True, Position=3)] $password,
 [String][Parameter(Mandatory=$True, Position=4)] $clusterName
)
			
$authInfo = [System.Text.Encoding]::UTF8.GetBytes(("{0}:{1}" -f $username, $password))
$authInfo = [System.Convert]::ToBase64String($authInfo)
				
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", "Basic $authinfo")
$headers.Add("Accept","application/json")

$uri = "https://$($clusterName).chsomaha.org:9440/PrismGateway/services/rest/v2.0/vms/$($uuid)?include_vm_disk_config=true&include_vm_nic_config=true"

$vm_get = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers

return $vm_get
}

function New-NutanixVMDisk {
<#
.SYNOPSIS
Adds a disk to a Nutanix VM specified by UUID from the Prism Element V2 API
.NOTES
Returns a task ID indicating the API is working on the request
Requires a VM UUID, disk size in GB, storage container UUID, username, password, and cluster name.
#>
param(
 [ValidatePattern("[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}")]
 [String][Parameter(Mandatory=$True, Position=1)] $uuid,
 [int][Parameter(Mandatory=$True, Position=2)] $diskSize,
 [ValidatePattern("[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}")]
 [String][Parameter(Mandatory=$True, Position=3)] $storageContainer,
 [String][Parameter(Mandatory=$True, Position=4)] $username,
 [String][Parameter(Mandatory=$True, Position=5)] $password,
 [String][Parameter(Mandatory=$True, Position=6)] $clusterName
)
			
$authInfo = [System.Text.Encoding]::UTF8.GetBytes(("{0}:{1}" -f $username, $password))
$authInfo = [System.Convert]::ToBase64String($authInfo)
				
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", "Basic $authinfo")
$headers.Add("Accept","application/json")
$headers.Add("Content-Type","application/json")

$uri = "https://$($clusterName).chsomaha.org:9440/PrismGateway/services/rest/v2.0/vms/$($uuid)/disks/attach"

$diskSizeBytes = $diskSize * 1GB

#########
$body = @"
{
    "vm_disks": [
    {
        "disk_address": {
            "device_bus": "SCSI"
        },
        "vm_disk_create": {
            "size": $diskSizeBytes,
            "storage_container_uuid": "$storageContainer"
        }
    }
    ]
}
"@
#########

$post = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body

return $post
}

Function New-VMDiskPartition
{
	<#
	.SYNOPSIS
	    The New-VMDiskPartiton function initializes, partitions, formats, and letters raw disks.

	.DESCRIPTION
	    The New-VMDiskPartiton function initializes, partitions, formats, and letters raw disks. Function will select the 1st if there are multiple raw disks of the same size.
	    You can specify the disk size in GB for sanity check, disk letter, volume label, partition scheme, and filesystem type.

	.EXAMPLE
        New-VMDiskPartition
        Formats an available raw disk with the next available letter in GPT with NTFS and label 'Data'

	.EXAMPLE
        New-VMDiskPartition -DiskSizeGB 25
        Formats an available raw disk that is exactly 25GB with the next available letter in GPT with NTFS and label 'Data'

	.EXAMPLE
        New-VMDiskPartition -DiskSizeGB 28 -DiskLetter G -VolumeLabel "Demo" -Scheme MBR -FileSystem FAT32
        Formats an available raw disk that is exactly 28GB with the letter G in MGR with FAT32 and label 'Demo'

	.NOTES
	    NAME:    New-VMDiskPartiton.ps1
	    AUTHOR:    Alex Hrdy
	    DATE:    4/28/2021
	    WWW:    nsoc.club
	    TWITTER: @nsocwx

	    VERSION HISTORY:
	    1.0	Initial Version
	#>
param
(
 [int][Parameter(Mandatory=$False, Position=1)] $DiskSizeGB,
 [ValidateLength(1,1)][ValidatePattern("^[A-Z.a-z]$")]
 [String][Parameter(Mandatory=$False, Position=2)] $DiskLetter,
 [ValidateLength(1,32)]
 [String][Parameter(Mandatory=$False, Position=3)] $VolumeLabel = "Data",
 [ValidateSet("MBR","GPT")]
 [String][Parameter(Mandatory=$False, Position=4)] $Scheme = "GPT",
 [ValidateSet("NTFS","FAT32","exFAT")]
 [String][Parameter(Mandatory=$False, Position=5)] $FileSystem = "NTFS"
 )
PROCESS{
    #body of script

    ## check that drive letter is safe
    $psDrives = Get-PSDrive
    if($psDrives.name -contains $DiskLetter){return "Drive letter $DiskLetter already exists"}

    ## pull current raw disks on the machine
    try
    {
        if($DiskSizeGB){
            $rawDisks = Get-Disk | Where-Object { $_.PartitionStyle -eq 'raw' -and [math]::Round(($_.Size/1GB)) -eq $diskSizeGB }
        }
        else{
            $rawDisks = Get-Disk | Where-Object { $_.PartitionStyle -eq 'raw' }
        }
        ## exit if no disks are found
        if($rawDisks -eq $null){return "No disk found with size: $DiskSizeGB"}
        else{
            Write-Verbose $rawDisks[0]
            $rawDisk = $rawDisks | Select-Object -First 1
        }
    }
    catch
    {
        Write-Verbose $_
        return "Failed to retrieve disk list from WMI"
    }
    
    ##  Initialize Disk
    try
    {
        $initialDisk = Initialize-Disk -UniqueId $rawDisk.uniqueid -PartitionStyle $Scheme -PassThru -ErrorAction Stop
    }
    catch
    {
        Write-Verbose $_
        return "Failed to initalize disk with ID $($rawDisk.UniqueId)"
    }

    ## Create Partition
    try
    {
        if($DiskLetter){
            $partitionDisk = New-Partition -InputObject $initialDisk -UseMaximumSize -DriveLetter $DiskLetter -ErrorAction Stop 
        }
        else{
            $partitionDisk = New-Partition -InputObject $initialDisk -UseMaximumSize -AssignDriveLetter -ErrorAction Stop
        }
        Write-Verbose $partitionDisk
    }
    catch
    {
        Write-Verbose $_
        return "Failed to partition disk with number $($initialDisk.DiskNumber)"
    }

    ## Format Volume
    try
    {
        $formatDisk = Format-Volume -DriveLetter $partitionDisk.DriveLetter -FileSystem $FileSystem -NewFileSystemLabel $VolumeLabel -Confirm:$False -ErrorAction Stop
        Write-Verbose $formatDisk
    }
    catch
    {
        Write-Verbose $_
        return "Failed to format disk with drive letter $($partitionDisk.DriveLetter)"
    }
    

	#$result = Get-PSDrive -ErrorAction Ignore | Where-Object name -like $DiskLetter -ErrorAction Ignore
	#return $result

}
END{
    #output from script

}
}




#Get Params from Ansible
$params = Parse-Args $args -supports_check_mode $true
$check_mode = Get-AnsibleParam -obj $params -name "_ansible_check_mode" -type "bool" -default $false

$username = Get-AnsibleParam -obj $params -name "username" -type "str" -failifempty $true
$password = Get-AnsibleParam -obj $params -name "password" -type "str" -failifempty $true
$uuid = Get-AnsibleParam -obj $params -name "uuid" -type "str" -failifempty $true
$diskSize = Get-AnsibleParam -obj $params -name "size" -type "int" -failifempty $true
$diskLetter = Get-AnsibleParam -obj $params -name "letter" -type "str" -failifempty $true
$diskLabel = Get-AnsibleParam -obj $params -name "label" -type "str" -failifempty $false
$clusterName = Get-AnsibleParam -obj $params -name "cluster" -type "str" -failifempty $true


## set result for return to ansible
$result = @{
    changed = $false
    uuid = $uuid
    drive_letter_exists = "False"
	drive_letter = $diskLetter
}

## verify disk letter is one character
if(!($diskLetter -match "^[A-z]$")){$diskLetter = $diskLetter.Split(":")}

## check count of current SCSI disks and add to result
try
{
    $currentDisks = Get-NutanixVMInfo -uuid $uuid -username $username -password $password -clusterName $clusterName | Select-Object -expandproperty vm_disk_info | Where-Object { $_.disk_address.device_bus -notlike 'IDE' }
    $result.existing_vdisk_count = $currentDisks.Count
}
catch
{
    Fail-Json -obj $result -message $_.Exception.Message
}

## check if the specified letter drive is in use or not
try
{
    $currentVolume = $null
    Update-HostStorageCache
    $currentVolume = Get-WmiObject -Class Win32_logicaldisk -Filter "DeviceID LIKE '$($diskLetter):'"
}
catch
{
    $currentVolume = $null
}

## if current drive letter is in use
if($currentVolume)
{
    $result.drive_letter_exists = "True"
    ## check size of current letter disk
    $result.drive_letter_exist_size = [math]::Round($currentVolume.Size/1GB)
    $result.drive_letter_exist_uuid = $currentDisks | Where-Object {$_.size -eq ($result.drive_letter_exist_size*1GB)} | Select-Object -ExpandProperty disk_address | Select-Object -ExpandProperty device_uuid
    ## if existing drive size greater or equal to spec
    if($result.drive_letter_exist_size -ge $diskSize)
    {
        $result.msg = "Existing drive greater or equal to specified size."
    }
    ## else current drive is too small
    else
    {
        $result.msg = "Existing drive smaller than specified size. Drive expansion is not yet supported."
    }
}
## else current drive letter is not in use
else
{
    ## check to see if raw disk already exists with correct size
    $raw = $null
    $raw = Get-Disk | Where-Object { $_.PartitionStyle -eq 'raw' -and [math]::Round(($_.Size/1GB)) -eq $diskSize }
    ## if not, create disk in Nutanix
    if($raw -eq $null)
    {
        ## create new disk using same storage container as C drive
        try
        {
            $storageContainer = $currentDisks | Where-Object { $_.disk_address.device_index -eq 0 } | Select-Object -ExpandProperty storage_container_uuid
            $result.storage_container = $storageContainer
            $result.task_uuid = New-NutanixVMDisk -uuid $uuid -diskSize $diskSize -storageContainer $storageContainer -username $username -password $password -clustername $clusterName
            $result.new_vdisk_count = ($currentDisks.Count + 1)

        }
        catch
        {
            Fail-Json -obj $result -message $_.Exception.Message
        }

        ## check for new disk existance
        $count = 1
        while($raw -eq $null -and $count -lt 20)
        {
            $raw = Get-Disk | Where-Object { $_.PartitionStyle -eq 'raw' -and [math]::Round(($_.Size/1GB)) -eq $diskSize }
            $count ++
            Start-Sleep -Seconds 1
        }

        ## bail if disk doesn't show up
        if($raw -eq $null){Fail-Json -obj $result -message "Disk created but not found on VM, API task may have failed."}      
    }

    ## format new disk
    try
    {
        if($diskLabel){$newPartition = New-VMDiskPartition -DiskSizeGB $diskSize -DiskLetter $diskLetter -VolumeLabel $diskLabel}
		else{$newPartition = New-VMDiskPartition -DiskSizeGB $diskSize -DiskLetter $diskLetter}
    }
    catch
    {
        Fail-Json -obj $result -message $_.Exception.Message
    }

    ## outputs
    $result.changed = $True
    $result.disk = $newPartition


}


Exit-Json -obj $result
