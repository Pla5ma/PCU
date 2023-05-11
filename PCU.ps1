Clear-Host

$Version                             ='v1.2.110523'
$ExcludedPaths                       =@('C:\users\all users','C:\users\default','C:\users\default user','C:\users\public')
$ExcludedAccountsForRetentionAndSize =@('Administrator','DefaultUser0')
$RetentionInDays                     =-365
$MaximumSizeInMB                     =1048576
$DeleteDotDirectories                =0
$LocalizedEventlogString             ='Account Name'
$DeleteLogFile                       =1

Function Write-LogFile($Content) {
    $Content | Out-File -Append -Force -FilePath $Env:SystemRoot\Temp\PCU.log
}

Function Delete-LogFile() {
    if ($DeleteLogFile) {
        if (Test-Path $Env:SystemRoot\Temp\PCU.log) {
            Remove-Item -Force $Env:SystemRoot\Temp\PCU.log
        }
    }
}

Function Write-StartupInformation {
    Write-LogFile('')
    Write-LogFile('Time:                            '+(Get-Date))
    Write-LogFile('Version:                         '+$Version)
    Write-LogFile('Excluded paths:                  '+$ExcludedPaths)
    Write-LogFile('Excluded accounts for retention: '+$ExcludedAccountsForRetentionAndSize)
    Write-LogFile('Retention in days:               '+$RetentionInDays)
    Write-LogFile('Maximum size in MB:              '+$MaximumSizeInMB)
    Write-LogFile('Delete . directories:            '+$DeleteDotDirectories)
}

Function Delete_Directory($DirectoryName) {
    Write-LogFile('*** Directory deletion routine started  ***')
    Write-Output ('*** Directory deletion routine started  ***')
    Write-LogFile('Processing directory:           ' + $DirectoryName)
    Write-Output ('Processing directory:           ' + $DirectoryName)

    Write-LogFile('Deleting directory - Fast')
    Write-Output ('Deleting directory - Fast')
    cmd /c "rd /q /s $DirectoryName" 2>&1 | Out-File -Append -Force -FilePath $Env:SystemRoot\Temp\PCU.log
    Write-LogFile('*** Fast directory deletion routine finished ***')
    Write-Output ('*** Fast directory deletion routine finished ***')
    Write-LogFile('Deleting directory - Slow')
    Write-Output ('Deleting directory - Slow')
    
    Get-ChildItem $DirectoryName -Recurse -force | Where-Object {$_.PSIsContainer -eq $true} | ForEach-Object {
        $ACL = Get-Acl $_.FullName
        $AccessRule= New-Object System.Security.AccessControl.FileSystemAccessRule($Everyone,'FullControl','ContainerInherit,Objectinherit','none','Allow')
        $ACL.AddAccessRule($AccessRule)
        $ACL.SetOwner($EveryoneIdentity)
        Write-LogFile ('Setting ACLs for sub directory: '+ $_.FullName)
        Set-Acl -aclobject $ACL -path $_.FullName 2>&1 | Out-File -Append -Force -FilePath $Env:SystemRoot\Temp\PCU.log
    }

    $ACL = Get-Acl $DirectoryName
    $AccessRule= New-Object System.Security.AccessControl.FileSystemAccessRule($Everyone,'FullControl','none','none','Allow')
    $ACL.AddAccessRule($AccessRule)
    $ACL.SetOwner($EveryoneIdentity)
    Write-LogFile('Setting ACLs for root directory')
    Write-Output ('Setting ACLs for root directory')
    Set-Acl -aclobject $ACL -path $DirectoryName 2>&1 | Out-File -Append -Force -FilePath $Env:SystemRoot\Temp\PCU.log

    Get-ChildItem $DirectoryName -Recurse | Where-Object {$_.PSIsContainer -eq $false} | ForEach-Object {
        $ACL = Get-Acl $_.FullName
        $AccessRule= New-Object System.Security.AccessControl.FileSystemAccessRule($Everyone,'FullControl','none','none','Allow')
        $ACL.AddAccessRule($AccessRule)
        $ACL.SetOwner($EveryoneIdentity)
        Write-LogFile('Setting ACLs:       '+ $_.FullName)
        Write-Output ('Setting ACLs:       '+ $_.FullName)
        Set-Acl -aclobject $ACL -path $_.FullName 2>&1 | Out-File -Append -Force -FilePath $Env:SystemRoot\Temp\PCU.log
    }

    cmd /c "rd /q /s $DirectoryName" 2>&1 | Out-File -Append -Force -FilePath $Env:SystemRoot\Temp\PCU.log
    Write-LogFile('*** Slow directory deletion routine finished ***')
    Write-Output ('*** Slow directory deletion routine finished ***')
}

Function FindAndExclude-InteractiveLoggedOnUsersAndLoadedProfiles() {
    $ExplorerProcesses = @(Get-WmiObject -Query "Select * FROM Win32_Process WHERE Name='explorer.exe'" -ErrorAction SilentlyContinue)
    If ($ExplorerProcesses.Count -ne 0) {
        ForEach ($ExplorerProcess in $ExplorerProcesses)
        {
            $global:ExcludedAccountsForRetentionAndSize+=$ExplorerProcess.GetOwner().User
            Write-LogFile('Excluded user:           '+$ExplorerProcess.GetOwner().User)
        }
    }
    foreach ($Profile in $ProfileListWMI) {
        if ($Profile.Loaded -eq $true) {
            $global:ExcludedPaths+=$Profile.LocalPath
            Write-LogFile('Excluded directories:    '+$Profile.LocalPath)
        }
    }
}

Delete-LogFile
Write-StartupInformation
Write-Output ('')
Write-Output '============================================================================================================================================================'
Write-Output ('Profile Cleanup Utility')
Write-Output ('danhil@microsoft.com')
Write-Output ($Version)
Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'
Write-Output ('')
Write-Output ('')

Write-LogFile('')
Write-LogFile('Building profile list Registry')
$ProfileListRegistry = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Recurse
Write-LogFile('Building profile list WMI')
$ProfileListWMI = Get-WmiObject Win32_UserProfile | Where-Object { $_.LocalPath -notlike 'C:\WINDOWS*'}
Write-LogFile('Getting localized Everyone identity')
$EveryoneSID = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$Everyone = ($EveryoneSID.Translate( [System.Security.Principal.NTAccount])).Value
$EveryoneIdentity = New-Object System.Security.Principal.NTAccount($Everyone)
Write-LogFile('Getting logon events')
$LogonEvents = Get-EventLog -LogName Security -InstanceId 4624
Write-LogFile('')
Write-LogFile('Getting interactive logged on users and loaded profiles')
FindAndExclude-InteractiveLoggedOnUsersAndLoadedProfiles



Write-Output 'RETENTION POLICY CHECK'
Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'
Write-LogFile ('')
Write-LogFile ('')
Write-LogFile ('RETENTION POLICY CHECK')
foreach ($Profile in $ProfileListWMI) {
    Write-LogFile('')
    Write-Output ('')
    Write-LogFile('Directory:               '+$Profile.LocalPath)
    Write-Output ('Directory:               '+$Profile.LocalPath)
    $ExcludedDirectory = $False
    foreach ($Account in $ExcludedAccountsForRetentionAndSize) {
        if ($Profile.LocalPath) {
            if ($Profile.LocalPath.tolower() -like '*'+$Account.tolower()+'*') {
                $ExcludedDirectory = $True                
            }
        }
    }
    foreach ($ExcludedPath in $ExcludedPaths) {
        if ($Profile.LocalPath.tolower() -eq $ExcludedPath.tolower()) {
            $ExcludedDirectory = $True
        }
    }
    Write-LogFile('Excluded:                '+$ExcludedDirectory)
    Write-Output ('Excluded:                '+$ExcludedDirectory)
    if (!$ExcludedDirectory) {

        $PathUser = (Split-Path $Profile.LocalPath -Leaf)
        if ($PathUser.Contains('.')) {
            $PathUser = $PathUser.Substring(0, $PathUser.LastIndexOf('.'))
        }

        $LastLogon = $null
        foreach ($Event in $LogonEvents) {
            $LogonAccount = (($Event.Message | Select-String ('.*' + $LocalizedEventlogString + ':.*') -AllMatches).Matches)[1].Value.ToString()
            $LogonAccount = $LogonAccount -replace ($LocalizedEventlogString + ':'), ''
            $LogonAccount = $LogonAccount -replace [char]9, ''
            $LogonAccount = $LogonAccount -replace ' ', ''
            $LogonAccount = $LogonAccount.Substring(0, $LogonAccount.Length - 1)
            if ($LogonAccount.Contains('@')) {
                $LogonAccount = $LogonAccount.Substring(0, $LogonAccount.LastIndexOf('@'))
            }
            if ($LogonAccount -ieq $PathUser) {
                $LastLogon = $Event.TimeGenerated
                break
            }
        }
        if (!$LastLogon) {
            Write-LogFile('Logon:                   No logon events found')
            Write-Output ('Logon:                   No logon events found')
            Write-LogFile('Valid:                   False')
            Write-Output ('Valid:                   False')
            Delete_Directory($Profile.LocalPath)
            Write-output ('Status:                  Deleted')
        } elseif ($LastLogon -lt (get-date).adddays($RetentionInDays)) {
            Write-LogFile('Logon:                   '+$LastLogon)
            Write-Output ('Logon:                   '+$LastLogon)
            Write-LogFile('Age:                     '+((get-date).Subtract($LastLogon).Days))
            Write-Output ('Age:                     '+((get-date).Subtract($LastLogon).Days))
            Write-LogFile('Valid:                   False')
            Write-Output ('Valid:                   False')
            Delete_Directory($Profile.LocalPath)
            Write-output ('Status:                  Deleted')
        } else {
            Write-LogFile('Logon:                   '+$LastLogon)
            Write-Output ('Logon:                   '+$LastLogon)
            Write-LogFile('Age:                     '+((get-date).Subtract($LastLogon).Days))
            Write-Output ('Age:                     '+((get-date).Subtract($LastLogon).Days))
            Write-LogFile('Valid:                   True')
            Write-Output ('Valid:                   True')
            Write-output ('Status:                  Untouched')
        }
    }
}
Write-Output ('')
Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'
Write-Output ('')

Write-Output 'MAXIMUM SIZE CHECK'
Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'
Write-LogFile ('')
Write-LogFile ('')
Write-LogFile ('MAXIMUM SIZE CHECK')
foreach ($Profile in $ProfileListWMI) {
    Write-LogFile('')
    Write-Output ('')
    Write-LogFile('Directory:               '+$Profile.LocalPath)
    Write-Output ('Directory:               '+$Profile.LocalPath)
    $ExcludedDirectory = $False
    foreach ($Account in $ExcludedAccountsForRetentionAndSize) {
        if ($Profile.LocalPath) {
            if ($Profile.LocalPath.tolower() -like '*'+$Account.tolower()+'*') {
                $ExcludedDirectory = $True                
            }
        }
    }
    foreach ($ExcludedPath in $ExcludedPaths) {
        if ($Profile.LocalPath.tolower() -eq $ExcludedPath.tolower()) {
            $ExcludedDirectory = $True
        }
    }
    Write-LogFile('Excluded:                '+$ExcludedDirectory)
    Write-Output ('Excluded:                '+$ExcludedDirectory)
    if (!$ExcludedDirectory) {
        $ProfileSize = ''
        $ProfileSize = [math]::round(((Get-ChildItem $Profile.LocalPath -Recurse -force 2> $null | Measure-Object -Sum Length | Select-Object -ExpandProperty Sum)/1048576),2)

        Write-LogFile('Size:                    '+$ProfileSize+'MB')
        Write-Output ('Size:                    '+$ProfileSize+'MB')
        if ($ProfileSize -le $MaximumSizeInMB) {

           Write-LogFile('Valid:                   True')
           Write-Output ('Valid:                   True')
           Write-output ('Status:                  Untouched')
        } else {
           Write-LogFile('Valid:                   False')
           Write-Output ('Valid:                   False')
           Delete_Directory($ProfileDirectory)            
           Write-output ('Status:                  Deleted')
        }
    }
}
Write-Output ('')
Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'
Write-Output ('')

Write-Output 'DIRECTORY CLEANUP - MISSING NTUSER.DAT'
Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'
Write-LogFile ('')
Write-LogFile ('')
Write-LogFile ('DIRECTORY CLEANUP - MISSING NTUSER.DAT')
$ProfileDirectories = (Get-ChildItem 'C:\users' | Where-Object { $_.PSIsContainer -eq $true} | ForEach-Object{$_.FullName}).tolower()
foreach ($ProfileDirectory in $ProfileDirectories) {
    Write-LogFile('')
    Write-Output ('')
    Write-LogFile('Directory:               '+$ProfileDirectory)
    Write-Output ('Directory:               '+$ProfileDirectory)
    $ExcludedDirectory = $False
    foreach ($ExcludedPath in $ExcludedPaths) {
        if ($ProfileDirectory -eq $ExcludedPath.tolower()) {
            $ExcludedDirectory = $True
        }
    }
    Write-LogFile('Excluded:                '+$ExcludedDirectory)
    Write-Output ('Excluded:                '+$ExcludedDirectory)
    if (!$ExcludedDirectory) {
        if (Test-Path ($ProfileDirectory + '\ntuser.dat')) {
           Write-LogFile('Valid:                   True')
           Write-Output ('Valid:                   True')
           Write-output ('Status:                  Untouched')
        } else {
           Write-LogFile('Valid:                   False')
           Write-Output ('Valid:                   False')
           Delete_Directory($ProfileDirectory)            
           Write-Output ('Status:                  Deleted')
        }
    }
}
Write-Output ('')
Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'
Write-Output ('')

Write-Output 'DIRECTORY CLEANUP - MISSING PROFILELIST ENTRY'
Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'
Write-LogFile ('')
Write-LogFile ('')
Write-LogFile ('DIRECTORY CLEANUP - MISSING PROFILELIST ENTRY')
$ProfileDirectories = (Get-ChildItem 'C:\users' | Where-Object { $_.PSIsContainer -eq $true} | ForEach-Object{$_.FullName}).tolower()
$ProfileImagePaths=$ExcludedPaths
foreach ($Profile in $ProfileListRegistry) {
    if (($Profile | Get-ItemProperty).Psobject.Properties | Where-Object { $_.Name -eq 'ProfileImagePath' -and $_.Value -notlike 'C:\WINDOWS*'} | Select-Object Value) {
        $ProfileImagePaths += ($Profile.GetValue('ProfileImagePath').tolower())
    }
}
foreach ($ProfileDirectory in $ProfileDirectories) {
    Write-LogFile('')
    Write-Output ('')
    Write-LogFile('Directory:               '+$ProfileDirectory)
    Write-Output ('Directory:               '+$ProfileDirectory)
    $ValidDirectory = $false
    foreach ($ProfileImagePath in $ProfileImagePaths) {
        if ($ProfileDirectory -eq $ProfileImagePath) {
            $ValidDirectory = $true
        }        
    }
    Write-LogFile('Valid:                   ' + $ValidDirectory)
    Write-Output ('Valid:                   ' + $ValidDirectory)
    if (!$ValidDirectory) {
        Delete_Directory($ProfileDirectory)
        Write-LogFile('Status:                  Deleted')
        Write-Output ('Status:                  Deleted')
    } else {
        Write-LogFile('Status:                  Untouched')
        Write-Output ('Status:                  Untouched')
    }
}
Write-Output ('')
Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'
Write-Output ('')

if ($DeleteDotDirectories) {
    Write-Output 'DIRECTORY CLEANUP - DOT DIRECTORY'
    Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'
    Write-LogFile ('')
    Write-LogFile ('')
    Write-LogFile ('DIRECTORY CLEANUP - DOT DIRECTORY')
    $ProfileDirectories = (Get-ChildItem 'C:\users' | Where-Object { $_.PSIsContainer -eq $true} | ForEach-Object{$_.FullName}).tolower()
    $ProfileImagePaths=$ExcludedPaths
    foreach ($Profile in $ProfileListRegistry) {
        if (($Profile | Get-ItemProperty).Psobject.Properties | Where-Object { $_.Name -eq 'ProfileImagePath' -and $_.Value -notlike 'C:\WINDOWS*'} | Select-Object Value) {
            $ProfileImagePaths += ($Profile.GetValue('ProfileImagePath').tolower())
        }
    }
    foreach ($ProfileDirectory in $ProfileDirectories) {
        Write-LogFile('')
        Write-Output ('')
        Write-LogFile('Directory:               '+$ProfileDirectory)
        Write-Output ('Directory:               '+$ProfileDirectory)
        $ValidDirectory = $true
        if ($ProfileDirectory -like '*.*') {
            $ValidDirectory = $false
        }
        Write-LogFile('Valid:                   '+$ValidDirectory)        
        Write-Output ('Valid:                   '+$ValidDirectory)
        if (!$ValidDirectory) {
            Delete_Directory($ProfileDirectory)
            Write-LogFile('Status:                  Deleted')
            Write-Output ('Status:                  Deleted')
        } else {
            Write-LogFile('Status:                  Untouched')
            Write-Output ('Status:                  Untouched')
        }
    }
    Write-Output ('')
    Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'
    Write-Output ('')
}

Write-Output 'REGISTRY CLEANUP - MISSING PROFILE DIRECTORY'
Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'
Write-LogFile ('')
Write-LogFile ('')
Write-LogFile ('REGISTRY CLEANUP - MISSING PROFILE DIRECTORY')
foreach ($Profile in $ProfileListRegistry) {
    if (($Profile | Get-ItemProperty).Psobject.Properties | Where-Object { $_.Name -eq 'ProfileImagePath' -and $_.Value -notlike 'C:\WINDOWS*'} | Select-Object Value) {
        Write-Output ('')
        Write-LogFile('')
        Write-LogFile('ProfileList Key:         '+$Profile.Name)
        Write-Output ('ProfileList Key:         '+$Profile.Name)
        Write-LogFile('Directory:               '+$Profile.GetValue('ProfileImagePath'))
        Write-Output ('Directory:               '+$Profile.GetValue('ProfileImagePath'))
        if (Test-Path $Profile.GetValue('ProfileImagePath') -PathType Container) {
            Write-LogFile('Valid:                   True')
            Write-Output ('Valid:                   True')
            Write-LogFile('Status:                  Untouched')
            Write-Output ('Status:                  Untouched')
        } else {
            Write-LogFile('Valid:                   False')
            Write-Output ('Valid:                   False')
            Remove-Item -Recurse -Force $Profile.PSPath 2>&1 | Out-File -Append -Force -FilePath $Env:SystemRoot\Temp\PCU.log
            Write-LogFile('Status:                  Deleted')
            Write-Output ('Status:                  Deleted')
        }
    }
}
Write-Output ('')
Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'

Write-Output ('')
Write-Output ('')
Write-Output '============================================================================================================================================================'  
