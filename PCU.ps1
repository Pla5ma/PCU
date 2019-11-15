Clear-Host

Write-Output ('')
Write-Output '============================================================================================================================================================'
Write-Output ('Profile Cleanup Utility')
Write-Output ('v0.93')
Write-Output ('danhil@microsoft.com')
Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'
Write-Output ('')
Write-Output ('')

$ExcludedPaths=@('C:\users\all users','C:\users\default','C:\users\default user','C:\users\public')
$ExcludedAccountsForRetention=@('Administrator')
$RetentionInDays=-40

$ProfileImagePaths=$ExcludedPaths
$ProfileListRegistry = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Recurse
$ProfileListWMI = Get-WmiObject Win32_UserProfile | Where-Object { $_.LocalPath -notlike 'C:\WINDOWS*'}


Write-Output 'RETENTION POLICY CHECK'
Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'
foreach ($Profile in $ProfileListWMI) {
    $ExcludedAccount = $False
    foreach ($Account in $ExcludedAccountsForRetention) {
        if ($Profile.LocalPath.tolower() -like '*'+$Account.tolower()+'*') {
            $ExcludedAccount = $True
        }
    }
    if (!$ExcludedAccount) {
        Write-Output ('')
        Write-Output ('Profile Directory: ' + $Profile.LocalPath)
        Write-Output ('LastUseTime:       ' + [Management.ManagementDateTimeConverter]::ToDateTime($Profile.LastUseTime))
        if ([Management.ManagementDateTimeConverter]::ToDateTime($Profile.LastUseTime) -lt (get-date).adddays($RetentionInDays)) {
            Write-Output ('Valid:             False')
            takeown.exe /R /D J /F $Profile.LocalPath | out-null
            icacls.exe $Profile.LocalPath /t /grant *S-1-1-0:F /inheritance:r | out-null
            Get-ChildItem $Profile.LocalPath -Recurse| Where-Object { $_.PSIsContainer -eq $false} | Set-ItemProperty -name IsReadOnly -value $false
            # Get-ChildItem $ProfileDirectory -Recurse -force | Remove-Item -Force
            cmd /c rmdir $ProfileDirectory /S /Q
            Write-output ('Status:            Deleted')
        } else {
            Write-Output ('Valid:             True')
            Write-output ('Status:            Untouched')
        }
    }
}
Write-Output ('')
Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'
Write-Output ('')

Write-Output 'DIRECTORY CLEANUP - *.AD Profile'
Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'
$ProfileDirectories = (Get-ChildItem 'C:\users' | Where-Object { $_.PSIsContainer -eq $true} | ForEach-Object {$_.FullName}).tolower()
foreach ($ProfileDirectory in $ProfileDirectories) {
    $ExcludedDirectory = $False
    foreach ($ExcludedPath in $ExcludedPaths) {
        if ($ProfileDirectory -eq $ExcludedPath.tolower()) {
            $ExcludedDirectory = $True
        }
    }
    if (!$ExcludedDirectory) {
        Write-Output ('')
        Write-Output ('Profile Directory: ' + $ProfileDirectory)
        if ($ProfileDirectory -notmatch ".ad") {
            Write-Output ('Valid:             True')
            Write-output ('Status:            Untouched')
        } else {
            Write-Output ('Valid:             False')
            Write-Output $ProfileDirectory
            # takeown.exe /R /D J /F $ProfileDirectory | out-null
            # takeown.exe /R /D J /F $ProfileDirectory
            # icacls.exe $ProfileDirectory /t /grant *S-1-1-0:F /inheritance:r
            # icacls.exe $ProfileDirectory /t /grant *S-1-1-0:F /inheritance:r | out-null
            # Get-ChildItem $ProfileDirectory -Recurse -force| Where-Object { $_.PSIsContainer -eq $false} | Set-ItemProperty -name IsReadOnly -value $false
            # Get-ChildItem $ProfileDirectory -Recurse -force | Remove-Item -Force
            cmd /c rmdir $ProfileDirectory /S /Q
            Write-output ('Status:            Deleted')
        }
    }
}


Write-Output 'DIRECTORY CLEANUP - MISSING NTUSER.DAT'
Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'
$ProfileDirectories = (Get-ChildItem 'C:\users' | Where-Object { $_.PSIsContainer -eq $true} | ForEach-Object {$_.FullName}).tolower()
foreach ($ProfileDirectory in $ProfileDirectories) {
    $ExcludedDirectory = $False
    foreach ($ExcludedPath in $ExcludedPaths) {
        if ($ProfileDirectory -eq $ExcludedPath.tolower()) {
            $ExcludedDirectory = $True
        }
    }
    if (!$ExcludedDirectory) {
        Write-Output ('')
        Write-Output ('Profile Directory: ' + $ProfileDirectory)
        if (Test-Path ($ProfileDirectory + '\ntuser.dat')) {
            Write-Output ('Valid:             True')
            Write-output ('Status:            Untouched')
        } else {
            Write-Output ('Valid:             False')
            Write-Output $ProfileDirectory
            takeown.exe /R /D J /F $ProfileDirectory | out-null
            icacls.exe $ProfileDirectory /t /grant *S-1-1-0:F /inheritance:r | out-null
            Get-ChildItem $ProfileDirectory -Recurse -force| Where-Object { $_.PSIsContainer -eq $false} | Set-ItemProperty -name IsReadOnly -value $false
            # Get-ChildItem $ProfileDirectory -Recurse -force | Remove-Item -Force
            cmd /c rmdir $ProfileDirectory /S /Q
            Write-output ('Status:            Deleted')
        }
    }
}
Write-Output ('')
Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'
Write-Output ('')

Write-Output 'DIRECTORY CLEANUP - MISSING PROFILELIST ENTRY'
Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'
$ProfileDirectories = (Get-ChildItem 'C:\users' | Where-Object { $_.PSIsContainer -eq $true} | ForEach-Object {$_.FullName}).tolower()
foreach ($Profile in $ProfileListRegistry) {
    if (($Profile | Get-ItemProperty).Psobject.Properties | Where-Object { $_.Name -eq 'ProfileImagePath' -and $_.Value -notlike 'C:\WINDOWS*'} | Select-Object Value) {
        $ProfileImagePaths += ($Profile.GetValue('ProfileImagePath').tolower())
    }
}
foreach ($ProfileDirectory in $ProfileDirectories) {
    Write-Output ('')
    $ValidDirectory = $false
    foreach ($ProfileImagePath in $ProfileImagePaths) {
        if ($ProfileDirectory -eq $ProfileImagePath) {
            $ValidDirectory = $true
        }        
    }
    Write-Output ('Profile Directory: ' + $ProfileDirectory)
    Write-Output ('Valid:             ' + $ValidDirectory)
    if (!$ValidDirectory) {
        takeown.exe /R /D J /F $ProfileDirectory | out-null
        icacls.exe $ProfileDirectory /t /grant *S-1-1-0:F /inheritance:r | out-null
        Get-ChildItem $ProfileDirectory -Recurse| Where-Object { $_.PSIsContainer -eq $false} | Set-ItemProperty -name IsReadOnly -value $false
        # Get-ChildItem $ProfileDirectory -Recurse -force | Remove-Item -Force
        cmd /c rmdir $ProfileDirectory /S /Q
        Write-output ('Status:            Deleted')
    } else {
        Write-output ('Status:            Untouched')
    }
}
Write-Output ('')
Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'
Write-Output ('')

Write-Output 'REGISTRY CLEANUP - MISSING PROFILE DIRECTORY'
Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'
foreach ($Profile in $ProfileListRegistry) {
    if (($Profile | Get-ItemProperty).Psobject.Properties | Where-Object { $_.Name -eq 'ProfileImagePath' -and $_.Value -notlike 'C:\WINDOWS*'} | Select-Object Value) {
        Write-Output ('')
        Write-Output ('ProfileList Key:   ' + $Profile.Name)
        Write-Output ('Profile Directory: ' + $Profile.GetValue('ProfileImagePath'))
        if (Test-Path $Profile.GetValue('ProfileImagePath') -PathType Container) {
            Write-Output ('Valid:             True')
            Write-output ('Status:            Untouched')
        } else {
            Write-Output ('Valid:             False')
            Remove-Item -Recurse -Force $Profile.PSPath
            Write-output ('Status:            Deleted')
        }
    }
}
Write-Output ('')
Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'

Write-Output ('')
Write-Output ('')
Write-Output '============================================================================================================================================================'
