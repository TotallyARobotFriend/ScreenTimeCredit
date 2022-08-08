# Screen Time Credit for u/oneinnerpiece

<#
    Warnings:
        1. I'm a random person on the internet, I've tried to notate everything so you know what's happening but be careful, PowerShell admin means full control to things you may not even know about.
        2. I wrote half of this during a 100 hour work week and the other half after coming back from PTO, sanity not promised...
        3. While I tested and tried to account for things, I may have missed something, let me know if you encounter any issues. :)

        


    Steps:
        Open PowerShell ISE
        Open a new script by pressing Ctrl+O in PowerShell ISE
        Paste this script
        Read through the notes
        Save file to C:\ScreenTime as UpdateChallenge.ps1
    
    
    This script uses information collected in the other script so yes, both do have to be run

#>

$ErrorActionPreference = 0 # Any errors in a command will be handled silently
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition # This is where the script lives so we can use this as the begining of our path to find the csv
$qaPath = "$scriptPath\questionsAnswers.csv"
$userPath = "$scriptPath\userData.csv"
$delimiter = [char]9 # Uses tab as a delimiter instead of a comma in case you use them in a question/answer

function Update-CaptainsLog([string]$Text,[switch]$FailFlag){
    # This is a very preferance based formatting of last 2 digits of the year - 2 digits of the month, 2 digits of the day a divider and then the time
    $time = Get-Date -Format "yy-MM-dd::hh:mm" # Sets an easily sortable format for the date
    $outputItems = @($time,$Text) -join $delimiter # Anything we want to output
    Out-File -LiteralPath "$scriptPath\Logs.csv" -Append -Encoding utf8 -Force -InputObject $outputItems # Sends the information to the file
    if($FailFlag){
        $cmd = {
            param([string]$msg)
                Write-Host $msg
                Read-Host "Press {Enter} to Exit" -AsSecureString # Secure string is just so that any text entered is a '*'
        } # Script blocks are nice ways to basically save a command for later, essentially a function in a variable
        Start-Process powershell -WindowStyle Maximized -ArgumentList "-command (Invoke-Command -ScriptBlock {$cmd} -ArgumentList $text)" # Open a new powershell window and let the child know to talk to you
        exit # Stops running THIS powershell script and terminates the session
    }
}

try{ $QandAs = Import-Csv -Path $qaPath -Delimiter $delimiter }  # Imports Questions and Answers for Password and Password Hint
catch{ Update-CaptainsLog "No Question and Answer CSV found, expected path of $qaPath" -FailFlag }
try{ $userData = Import-Csv -Path $userPath -Delimiter $delimiter } # Imports user data
catch{ Update-CaptainsLog "No userData Found, expected path of $userPath" -FailFlag }

#region Random Q&A
$maxTally = $QandAs.Tally | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum # Find the highest Tally value to weight random selection
$weightedList = New-Object System.Collections.Generic.List[object] # Make it more likely to get an unused question
foreach($item in $QandAs){
    if($item.LastUsed -eq 'TRUE'){
        $Script:oldPasswordValue = $item.Answers # Save this in case updating later doesn't work
        $item.LastUsed = '' # Set it to blank since we'll have a new one
        continue # Don't do anything else for this item and start at the top of the loop with the next item
    } # Skips the Question and Answer that was last used.
    
    $iterations = $maxTally - ( $item.Tally -as [int] ) + 1 # This is adding the Question and Answer to the weighted list inversely to the number of times it's been used
    for ($i = 0; $i -lt $iterations; $i++){
        $weightedList.Add($item)
    }
}
$randomSelection = Get-Random -Minimum 0 -Maximum ($weightedList.Count) # Picks a number between 0 and the total items in the list
$newQandA = ( $QandAs | Where-Object { $_ -like $weightedList[$randomSelection] } )  # Grabs the data for the new random QandA
#endregion

try{ Set-LocalUser -Name $userData.UserName -Password (ConvertTo-SecureString $newQandA.Answers -AsPlainText -Force) | Out-Null } # Set new password
catch{ Update-CaptainsLog "Unable to update Password" -FailFlag }

try{ Set-ItemProperty -Path "HKLM:\SAM\SAM\Domains\Account\Users\$($userData.RID)" -Name UserPasswordHint -Value $newQandA.Questions | Out-Null } # Set new password hint
catch{
    Update-CaptainsLog "Unable to update Password Hint" -FailFlag
    try{ Set-LocalUser -Name $userData.UserName -Password (ConvertTo-SecureString $Script:oldPasswordValue -AsPlainText -Force) | Out-Null }
    catch{ Update-CaptainsLog "Password could not be updated backwards, Password and Password Hint mixmatch" -FailFlag }
}

#region Update CSV
$newQandA.Tally = [int]($newQandA.Tally) + 1 # Add a new tally for changing the password
$newQandA.LastUsed = 'TRUE'
Out-File -LiteralPath $qaPath -InputObject (@("Questions","Answers","Tally","LastUsed") -join $delimiter)
$QandAs | ForEach-Object { Out-File -LiteralPath $qaPath -Append -InputObject ((ConvertTo-Csv $QandAs[0] -NoTypeInformation -Delimiter ([char]9))[-1]) -Force }
#endregion
