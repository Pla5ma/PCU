Clear-Host

$Version                      ='v0.99.4'
$ExcludedPaths                =@('C:\users\all users','C:\users\default','C:\users\default user','C:\users\public')
$ExcludedAccountsForRetention =@('Administrator','DefaultUser0')
$RetentionInDays              =-40
$DeleteDotDirectories         =1

Function Write-LogFile($Content) {
    $Content | Out-File -Append -Force -FilePath $Env:SystemRoot\Temp\PCU.log
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

    Write-LogFile ('Deleting directory')
    cmd /c "rd /q /s $DirectoryName" 2>&1 | Out-File -Append -Force -FilePath $Env:SystemRoot\Temp\PCU.log
    Write-LogFile('*** Directory deletion routine finished ***')
}

Write-StartupInformation
Write-Output ('')
Write-Output '============================================================================================================================================================'
Write-Output ('Profile Cleanup Utility')
Write-Output ($Version)
Write-Output ('danhil@microsoft.com')
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

Write-Output 'RETENTION POLICY CHECK'
Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'
Write-LogFile ('')
Write-LogFile ('')
Write-LogFile ('RETENTION POLICY CHECK')
foreach ($Profile in $ProfileListWMI) {
    Write-LogFile ('')
    Write-LogFile('ACCOUNT:     '+(Split-Path $Profile.LocalPath -Leaf))
    $ExcludedAccount = $False
    foreach ($Account in $ExcludedAccountsForRetention) {
        if ($Profile.LocalPath) {
            if ($Profile.LocalPath.tolower() -like '*'+$Account.tolower()+'*') {
                $ExcludedAccount = $True                
            }
        }
    }
    Write-LogFile ('Excluded:    '+$ExcludedAccount)
    if (!$ExcludedAccount) {
        if (($Profile.LastUseTime -ne '') -and ($Profile.LastUseTime)) {
            Write-Output ('')
            Write-Output ('Profile Directory: ' + $Profile.LocalPath)
            Write-LogFile ('LastUseTime: ' + [Management.ManagementDateTimeConverter]::ToDateTime($Profile.LastUseTime))
            Write-Output ('LastUseTime:       ' + [Management.ManagementDateTimeConverter]::ToDateTime($Profile.LastUseTime))
            if ([Management.ManagementDateTimeConverter]::ToDateTime($Profile.LastUseTime) -lt (get-date).adddays($RetentionInDays)) {
                Write-LogFile ('Valid:       False')
                Write-Output ('Valid:             False')
                Delete_Directory($ProfileDirectory)
                Write-output ('Status:            Deleted')
            } else {
                Write-LogFile ('Valid:       True')
                Write-Output ('Valid:             True')
                Write-output ('Status:            Untouched')
            }
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
