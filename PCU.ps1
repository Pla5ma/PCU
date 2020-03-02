Clear-Host



Write-Output ('')

Write-Output '============================================================================================================================================================'

Write-Output ('Profile Cleanup Utility')

Write-Output ('v0.99')

Write-Output ('danhil@microsoft.com')

Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'

Write-Output ('')

Write-Output ('')



$ExcludedPaths                =@('C:\users\all users','C:\users\default','C:\users\default user','C:\users\public')

$ExcludedAccountsForRetention =@('Administrator','DefaultUser0')

$RetentionInDays              =-40



$ProfileImagePaths=$ExcludedPaths

$ProfileListRegistry = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Recurse

$ProfileListWMI = Get-WmiObject Win32_UserProfile | Where-Object { $_.LocalPath -notlike 'C:\WINDOWS*'}

$EveryoneSID = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')

$Everyone = ($EveryoneSID.Translate( [System.Security.Principal.NTAccount])).Value

$EveryoneIdentity = New-Object System.Security.Principal.NTAccount($Everyone)



Function Delete_Directory($DirectoryName) {

    Get-ChildItem $DirectoryName -Recurse -force | Where-Object {$_.PSIsContainer -eq $true} | ForEach-Object {

        $ACL = Get-Acl $_.FullName

        $AccessRule= New-Object System.Security.AccessControl.FileSystemAccessRule($Everyone,'FullControl','ContainerInherit,Objectinherit','none','Allow')

        $ACL.AddAccessRule($AccessRule)

        $ACL.SetOwner($EveryoneIdentity)

        Set-Acl -aclobject $ACL -path $_.FullName

    }

    Get-ChildItem $DirectoryName -force | Where-Object {$_.PSIsContainer -eq $true} | ForEach-Object {

        $ACL = Get-Acl $_.FullName

        $AccessRule= New-Object System.Security.AccessControl.FileSystemAccessRule($Everyone,'FullControl','ContainerInherit,Objectinherit','none','Allow')

        $ACL.AddAccessRule($AccessRule)

        $ACL.SetOwner($EveryoneIdentity)

        Set-Acl -aclobject $ACL -path $_.FullName              

    }

    Get-ChildItem $DirectoryName -Recurse | Where-Object {$_.PSIsContainer -eq $false} | ForEach-Object {

        $ACL = Get-Acl $_.FullName

        $AccessRule= New-Object System.Security.AccessControl.FileSystemAccessRule($Everyone,'FullControl','none','none','Allow')

        $ACL.AddAccessRule($AccessRule)

        $ACL.SetOwner($EveryoneIdentity)

        Set-Acl -aclobject $ACL -path $_.FullName

    }
    
    cmd /c "rd /q /s $DirectoryName"

}



Write-Output 'RETENTION POLICY CHECK'

Write-Output '------------------------------------------------------------------------------------------------------------------------------------------------------------'

foreach ($Profile in $ProfileListWMI) {

    $ExcludedAccount = $False

    foreach ($Account in $ExcludedAccountsForRetention) {

        if ($Profile.LocalPath) {

            if ($Profile.LocalPath.tolower() -like '*'+$Account.tolower()+'*') {

                $ExcludedAccount = $True

            }

        }

    }

    if (!$ExcludedAccount) {

        if (($Profile.LastUseTime -ne '') -and ($Profile.LastUseTime)) {

            Write-Output ('')

            Write-Output ('Profile Directory: ' + $Profile.LocalPath)

            Write-Output ('LastUseTime:       ' + [Management.ManagementDateTimeConverter]::ToDateTime($Profile.LastUseTime))

            if ([Management.ManagementDateTimeConverter]::ToDateTime($Profile.LastUseTime) -lt (get-date).adddays($RetentionInDays)) {

                Write-Output ('Valid:             False')

                Delete_Directory($ProfileDirectory)

                Write-output ('Status:            Deleted')

            } else {

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

$ProfileDirectories = (Get-ChildItem 'C:\users' | Where-Object { $_.PSIsContainer -eq $true} | ForEach-Object{$_.FullName}).tolower()

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

$ProfileDirectories = (Get-ChildItem 'C:\users' | Where-Object { $_.PSIsContainer -eq $true} | ForEach-Object{$_.FullName}).tolower()

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

        Delete_Directory($ProfileDirectory)

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
