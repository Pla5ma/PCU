Clear-Host

$Version                      ='v1.0.060121 RC1'
$ExcludedPaths                =@('C:\users\all users','C:\users\default','C:\users\default user','C:\users\public')
$ExcludedAccountsForRetention =@('Administrator','DefaultUser0')
$RetentionInDays              =-40
$DeleteDotDirectories         =1
$LocalizedEventlogString      ='Kontoname'
$DeleteLogFile                =1

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
    Write-LogFile('Excluded accounts for retention: '+$ExcludedAccountsForRetention)
    Write-LogFile('Retention in days:               '+$RetentionInDays)
    Write-LogFile('Delete . directories:            '+$DeleteDotDirectories)
}

Function Delete_Directory($DirectoryName) {
    Write-LogFile('*** Directory deletion routine started  ***')
    Write-LogFile ('Processing directory:           ' + $DirectoryName)

    Write-LogFile ('Deleting directory - Fast')
    cmd /c "rd /q /s $DirectoryName" 2>&1 | Out-File -Append -Force -FilePath $Env:SystemRoot\Temp\PCU.log
    Write-LogFile('*** Fast directory deletion routine finished ***')

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
    Write-LogFile ('Setting ACLs for root directory')
    Set-Acl -aclobject $ACL -path $DirectoryName 2>&1 | Out-File -Append -Force -FilePath $Env:SystemRoot\Temp\PCU.log

    Get-ChildItem $DirectoryName -Recurse | Where-Object {$_.PSIsContainer -eq $false} | ForEach-Object {
        $ACL = Get-Acl $_.FullName
        $AccessRule= New-Object System.Security.AccessControl.FileSystemAccessRule($Everyone,'FullControl','none','none','Allow')
        $ACL.AddAccessRule($AccessRule)
        $ACL.SetOwner($EveryoneIdentity)
        Write-LogFile ('Setting ACLs:       '+ $_.FullName)
        Set-Acl -aclobject $ACL -path $_.FullName 2>&1 | Out-File -Append -Force -FilePath $Env:SystemRoot\Temp\PCU.log
    }

    Write-LogFile ('Deleting directory - Slow')
    cmd /c "rd /q /s $DirectoryName" 2>&1 | Out-File -Append -Force -FilePath $Env:SystemRoot\Temp\PCU.log
    Write-LogFile('*** Slow directory deletion routine finished ***')
}

Delete-LogFile
pause
Write-StartupInformation
pause
Write-Output ('')
Write-Output '============================================================================================================================================================'
Write-Output ('Profile Cleanup Utility')
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
Write-LogFile('Getting machine domain')
$MachineDomain = (Get-WmiObject Win32_ComputerSystem).Domain
Write-LogFile('Getting logon events')
$LogonEvents = Get-EventLog -LogName Security -InstanceId 4624

Write-Output 'RETENTION POLICY CHECK'
Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'
Write-LogFile ('')
Write-LogFile ('')
Write-LogFile ('RETENTION POLICY CHECK')
foreach ($Profile in $ProfileListWMI) {
    Write-LogFile ('')
    Write-Output ('')
    Write-LogFile('PROFILE:     '+$Profile.LocalPath)
    Write-Output ('PROFILE:           '+$Profile.LocalPath)
    $ExcludedDirectory = $False
    foreach ($Account in $ExcludedAccountsForRetention) {
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
    Write-LogFile ('Excluded:    '+$ExcludedDirectory)
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
            Write-LogFile ('Logon:       No logon events found')
            Write-Output ('Logon:             No logon events found')
            Write-LogFile ('Valid:       False')
            Write-Output ('Valid:             False')
            Delete_Directory($Profile.LocalPath)
            Write-output ('Status:            Deleted')
        } elseif ($LastLogon -lt (get-date).adddays($RetentionInDays)) {
            Write-LogFile ('Logon:       '+$LastLogon)
            Write-Output ('Logon:             '+$LastLogon)
            Write-LogFile ('Age:         '+((get-date).Subtract($LastLogon).Days))
            Write-Output ('Age:               '+((get-date).Subtract($LastLogon).Days))
            Write-LogFile ('Valid:       False')
            Write-Output ('Valid:             False')
            Delete_Directory($Profile.LocalPath)
            Write-output ('Status:            Deleted')
        } else {
            Write-LogFile ('Logon:       '+$LastLogon)
            Write-Output ('Logon:             '+$LastLogon)
            Write-LogFile ('Age:         '+((get-date).Subtract($LastLogon).Days))
            Write-Output ('Age:               '+((get-date).Subtract($LastLogon).Days))
            Write-LogFile ('Valid:       True')
            Write-Output ('Valid:             True')
            Write-output ('Status:            Untouched')
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
    Write-LogFile ('')
    Write-LogFile('DIRECTORY: '+$ProfileDirectory)
    $ExcludedDirectory = $False
    foreach ($ExcludedPath in $ExcludedPaths) {
        if ($ProfileDirectory -eq $ExcludedPath.tolower()) {
            $ExcludedDirectory = $True
        }
    }
    Write-LogFile ('Excluded:  '+$ExcludedDirectory)
    if (!$ExcludedDirectory) {
        Write-Output ('')
        Write-Output ('Profile Directory: ' + $ProfileDirectory)
        if (Test-Path ($ProfileDirectory + '\ntuser.dat')) {
           Write-LogFile ('Valid:     True')
           Write-Output ('Valid:             True')
           Write-output ('Status:            Untouched')
        } else {
            Write-LogFile ('Valid:     False')
            Write-Output ('Valid:             False')
            Delete_Directory($ProfileDirectory)            
            Write-output ('Status:            Deleted')
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
    Write-LogFile ('')
    Write-LogFile('DIRECTORY: '+$ProfileDirectory)
    Write-Output ('Profile Directory: ' + $ProfileDirectory)
    Write-Output ('')
    $ValidDirectory = $false
    foreach ($ProfileImagePath in $ProfileImagePaths) {
        if ($ProfileDirectory -eq $ProfileImagePath) {
            $ValidDirectory = $true
        }        
    }
    Write-LogFile('Valid:     ' + $ValidDirectory)
    Write-Output ('Valid:             ' + $ValidDirectory)
    if (!$ValidDirectory) {
        Delete_Directory($ProfileDirectory)
        Write-output ('Status:            Deleted')
    } else {
        Write-output ('Status:            Untouched')
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
        Write-LogFile ('')
        Write-LogFile('DIRECTORY: '+$ProfileDirectory)
        Write-Output ('Profile Directory: ' + $ProfileDirectory)
        Write-Output ('')
        $ValidDirectory = $true
        if ($ProfileDirectory -like '*.*') {
            $ValidDirectory = $false
        }
        Write-LogFile('Valid:     ' + $ValidDirectory)        
        Write-Output ('Valid:             ' + $ValidDirectory)
        if (!$ValidDirectory) {
            Delete_Directory($ProfileDirectory)
            Write-output ('Status:            Deleted')
        } else {
            Write-output ('Status:            Untouched')
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
        Write-LogFile ('')
        Write-LogFile('PROFILELIST KEY:   ' + $Profile.Name)
        Write-Output ('ProfileList Key:   ' + $Profile.Name)
        Write-LogFile('Profile Directory: ' + $Profile.GetValue('ProfileImagePath'))
        Write-Output ('Profile Directory: ' + $Profile.GetValue('ProfileImagePath'))
        if (Test-Path $Profile.GetValue('ProfileImagePath') -PathType Container) {
            Write-LogFile('Valid:             True')
            Write-Output ('Valid:             True')
            Write-output ('Status:            Untouched')
        } else {
            Write-LogFile('Valid:             False')
            Write-Output ('Valid:             False')
            Remove-Item -Recurse -Force $Profile.PSPath 2>&1 | Out-File -Append -Force -FilePath $Env:SystemRoot\Temp\PCU.log
            Write-output ('Status:            Deleted')
        }
    }
}
Write-Output ('')
Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'

Write-Output ('')
Write-Output ('')
Write-Output '============================================================================================================================================================'  
