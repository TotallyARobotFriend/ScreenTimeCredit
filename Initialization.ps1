# Screen Time Credit for u/oneinnerpiece

<#
    Warnings:
        1. This requires Admin permisisons to run, because of this we get to...
        2. I'm a random person on the internet, I've tried to notate everything so you know what's happening but be careful, PowerShell admin means full control to things you may not even know about.
        3. This messes with access to a value in the Registry that is intentionally locked down to reduce chances of getting hacked.
        4. If you don't want the kiddo changing the password beyond the script, you have to use a service account (handled in the script), outside of an Enterprise Domain, service accounts are more "all or nothing", this technically increases your risk
        5. Again, I'm a random person that just threw a random big-a** script on the screen, please be careful!
        6. I wrote half of this during a 100 hour work week and the other half after coming back from PTO, sanity not promised...
        7. While I tested and tried to account for things, I may have missed something, let me know if you encounter any issues. :)
        


    Steps:
        Open PowerShell ISE as an administrator
        Run this script
            Paste this script into the Script Pane (white part with the 1)
            Read through the notes, I did my best to notate everything!
            Press the F5 key to run the script
        You will be prompted at multiple points for more information


    This script modifys your system for the desired changes, collects data required to make said changes, creates a scheduled task, and saves needed files in its directory

#>

#region Functions
function Update-UserPasswordHint(){
    Param(
        [Parameter(Mandatory,Position=0)]
        [ValidateLength(1,100)] # I have no idea what the limit is so I set it as 100
        [string]$Hint,
        [Parameter(Position=1)]
        [ValidateLength(8,8)]
        [string]$RID
    )
    if(!$RID){$RID = ( Import-Csv $Script:userFilePath | Select-Object -ExpandProperty RID ) }
    $path = "HKLM:\SAM\SAM\Domains\Account\Users\$RID"
    $passwordHintExists = [bool](Get-ItemProperty -Path $path -Name UserPasswordHint -ErrorAction SilentlyContinue)
    if(!$exists){ New-ItemProperty -Path $path -PropertyType string -Name UserPasswordHint | Out-Null }
    Set-ItemProperty -Path $path -Name UserPasswordHint -Value $Hint
}

function Update-UserPasswordAndHint(){
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(Mandatory,Position=0)]
        [ValidateLength(1,100)] # I have no idea what the limit is so I set it as 100
        [string]$Hint,
        [Parameter(Mandatory,Position=2)]
        [string]$NewPassword,
        [Parameter(Mandatory,Position=3,ParameterSetName="Both")]
        [ValidateLength(8,8)]
        [string]$RID,
        [Parameter(Mandatory,Position=4,ParameterSetName="Both")]
        $UserName
    )
    if(!$RID){
        $csv = Import-Csv $Script:userFilePath
        $RID = $csv.RID
        $UserName = $csv.UserName
    }

    Set-LocalUser -Name $UserName -Password (ConvertTo-SecureString $NewPassword -AsPlainText -Force)
    Update-UserPasswordHint -RID $RID -Hint $Hint
}

function Add-TaskToDisplay(){
    Param(
        [Parameter(Mandatory,Position=0)]
        [string]$NewTask,
        [switch]$Failed
    )
    DynamicParam{
        $paramaterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        if($Failed){
            $parameterName = "Reason"
            $parameterType = [string]
            $attribute = New-Object System.Management.Automation.ParameterAttribute
            $attribute.Mandatory = $true
            $parameterCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $parameterCollection.Add($attribute)
            $dynamicParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($parameterName, $parameterType, $parameterCollection)
            $paramaterDictionary.Add($parameterName, $dynamicParameter)
        }
        Else{
            $parameterNames = @("Pause","Display")
            $parameterType = [switch]
            foreach($parameterName in $parameterNames){
                $parameterCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $parameterCollection.Add($(New-Object System.Management.Automation.ParameterAttribute))
                $dynamicParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($parameterName, $parameterType, $parameterCollection)
                $paramaterDictionary.Add($parameterName, $dynamicParameter)
            }
        }
        return $paramaterDictionary
    }

    Process{
        $Script:tasksCompleted.Add($( @{ $NewTask = $( ! ($Failed) ) } )) | Out-Null
        if($Failed){
            Clear-Host
            foreach($task in $Script:tasksCompleted){ Display-Task }
            
            if($Reason -ne ''){
                throw $Reason
                stop
            }
        }

        if($Display){ foreach($task in $Script:tasksCompleted){ Display-Task } }
        Else{ Display-Task $Script:tasksCompleted[-1] }
        if($Pause){
            pause
            Clear-Host
        }
    }
}

function Display-Task($Task){
    [pscustomobject]@{
        Task = $Task.Keys -as [string]
        Status = [char]::ConvertFromUtf32("0x$(if($Task.Values){'2705'}Else{'274E'})")
    }
}

function NoCSVProvided(){
    Write-Host "Password and PasswordHint are blank right now" -ForegroundColor Cyan -NoNewline
    Write-Host ", it is strongly reccomended to supply at least one Q&A"
    $userChoice = $Host.UI.PromptForChoice("Start CSV", "Do you want to supply a few Q&As now?", [System.Management.Automation.Host.ChoiceDescription[]]((New-Object System.Management.Automation.Host.ChoiceDescription '&Yes'), (New-Object System.Management.Automation.Host.ChoiceDescription '&No')), 1) # Prompt user for how to fill in CSV
    if($userChoice -eq 0){
        do{
            Clear-Host
            Write-Host "'Q' to Quit"
            $question = Read-Host "Please supply a Question"
            if($question -match '^(?:q|Q)$'){ break } # break if user gives a q or Q and nothing else
            $answer   = Read-Host "Please supply an Answer"
            Out-File -LiteralPath $Script:quesitonFilePath -Append -InputObject (@($question,$answer,0) -join $Script:delimiter) # Export Q&A item to desired format
        }while($true)
    }
    Else{
        Write-Host "Please be sure to update the CSV later"
        Write-Host "Reminder, Password and PasswordHint are blank right now."
    }
}

function Generate-ServiceAccount(){
    Add-Type -AssemblyName System.Web # The assembly that contains a password generator
    $gibberish = [System.Web.Security.Membership]::GeneratePassword(20,2) # Generates a random password 20 characters long with at least 2 special characters
    
    $serviceAccountName = "s_ScreenTimeCredit" # What the account will be named
    $serviceAccountPassword = "iL0veMyk1ds_$gibberish" # The plain text password of the service account with some randomness so that no else in this forum will know it either!
    Add-TaskToDisplay -NewTask "Generate Password: $serviceAccountPassword"
    
    $serviceAccountSecureStringPassword = ConvertTo-SecureString -String $serviceAccountName -AsPlainText -Force # Converts the plain text to a secured object
    $Script:credentialsToRunTask = New-Object System.Management.Automation.PSCredential ($serviceAccountName, $serviceAccountPassword) # Creating credential object to use later
    Remove-Variable gibberish,serviceAccountPassword # Clearing these out ASAP, not a huge difference but try where you can!
    
    New-LocalUser -AccountNeverExpires:$true -Disabled:$false -FullName $serviceAccountName -Name $serviceAccountName -Password $serviceAccountSecureStringPassword | Out-Null # Create the Service Account
    Add-LocalGroupMember -Group Administrators -Member $serviceAccountName # Delegated permissions outside of a Domain are lacking
    Add-TaskToDisplay -NewTask "Create Service Account"
}
#endregion

#region Getting Started
$Script:userData = [pscustomobject]@{UserName=$null;RID=$null } # This is a PowerShell object that we'll store information about the child's account in for easier reference
$Script:tasksCompleted = New-Object System.Collections.ArrayList # Just a storage for displaying what tasks are done
$Script:delimiter = [char]9 # Uses tab as a delimiter instead of a comma in case you use them in a question/answer
#Requires -RunAsAdministrator
Clear-Host
#endregion

#region All About The User
$optionsCollection = New-Object System.Collections.ArrayList # Temporary home to add choiceDescriptions
$optionsCollection.Add($(New-Object System.Management.Automation.Host.ChoiceDescription '{New Account}', 'Create a new account for your child')) | Out-Null # Add option for a new account to optionsCollection
$localUsers = Get-LocalUser | Where-Object { $_.Enabled } # Pull local users on PC
ForEach-Object -InputObject $localUsers -Process { $optionsCollection.Add($(New-Object System.Management.Automation.Host.ChoiceDescription $_.Name, $_.Description)) | Out-Null } # Add each user to optionsCollection as a ChoiceDescription
$userChoice = $Host.UI.PromptForChoice("Account Selection", "Select account you wish to apply management", ([System.Management.Automation.Host.ChoiceDescription[]]$optionsCollection), -1) # Provide prompt to user, -1 means no default choice
$Script:userData.UserName = switch ($userChoice){
    -1 { Add-TaskToDisplay -NewTask "Find Account" -Failed -Reason "User Cancelled" } # User cancelled
    0 {
        $newUserName = Read-Host # Prompts for username
        if($newUserName.Trim() -eq ''){ Add-TaskToDisplay -NewTask "Create Account" -Failed -Reason "No Name Provided" }
        $newUserName # sets the variable "userName" as user-inputted newUserName
        New-LocalUser -Name $newUserName -FullName $newUserName -AccountNeverExpires -Disabled:$false -Description "Child Account" -NoPassword | Add-LocalGroupMember -Group Users # Creates new account for child and gives them User rights
        Add-TaskToDisplay "Create Account"
    } # User choice to create a new account
    Default { $optionsCollection[$userChoice].Label } # Sets the variable "userName" as the user-selected value from LocalUsers
}
Add-TaskToDisplay "Find UserName"
Clear-Variable optionsCollection,localUsers,userChoice,newUserName # Cleaning up some as we go
#endregion

#region User Password Permissions
$userChoice = $Host.UI.PromptForChoice("Restrict Password", "Do you want to disable them changing their own password?", [System.Management.Automation.Host.ChoiceDescription[]]((New-Object System.Management.Automation.Host.ChoiceDescription '&Yes'), (New-Object System.Management.Automation.Host.ChoiceDescription '&No')), 0) # Prompt user for pre-prepared CSV
switch ($userChoice){
    0 {
        Set-LocalUser -Name $Script:userData.UserName -UserMayChangePassword:$false # User will not be allowed to update their password themselves, it will be updated via a Script only
        Add-TaskToDisplay "Restrict Password Updates"
        $Script:RestrictPassword = $true # Reference for later ;)
    } # Yes, password will be restricted
    Default {
        $Script:RestrictPassword = $false
        Add-TaskToDisplay -NewTask "Restrict Password Updates" -Failed -Reason ''
    } # Cancelled or "No"
}
#endregion

#region Service Account
$userChoice = $Host.UI.PromptForChoice("Service Account", "Do you want a service account to run this?`n`nI reccomend 'Yes' so you don't have to think about it again.", [System.Management.Automation.Host.ChoiceDescription[]]((New-Object System.Management.Automation.Host.ChoiceDescription '&Yes'), (New-Object System.Management.Automation.Host.ChoiceDescription '&No')), 0) # Prompt user for service account or own credentials to manage the script
switch ($userChoice){
    1 { 
        try{ $Script:credentialsToRunTask = Get-Credential -Credential $env:USERNAME } # Get user's own credentials to run the task
        catch{ Generate-ServiceAccount } # User cancelled
    } # User Credentials
    Default { Generate-ServiceAccount } # Service Account Credentials
}
#endregion

#region Setting Files and Variables
$Script:rootPath = "C:\ScreenTimeCredit" # Where the files needed will be placed; editable but I suggest leaving it to avoid potential issues
New-Item -ItemType Directory -Path $rootPath | Out-Null # Create directory to save information for future scripts to refer to including the Q&As
Add-TaskToDisplay "Create Directory"
$Script:quesitonFilePath = "$rootPath\QAs.csv" # Path to the CSV of Questions and Answers
Out-File -LiteralPath $Script:quesitonFilePath -InputObject (@("Questions","Answers","Tally","LastUsed") -join $Script:delimiter) # Export desired headers
$Script:userFilePath = "$rootPath\User.csv" # Where we will store information about the account for the future script
Add-TaskToDisplay -NewTask "Create Files"
#endregion

#region ACLs
#region Set ACL on new Directory
if(! ($Script:RestrictPassword)){
    # If child will have access to their own password, they'll need access to directory of new passwords
    $acl = Get-Acl -LiteralPath $rootPath # Get ACL of new directory
    $fileSystemAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule @( # Create an object of rules
        $Script:userData.UserName # Set to whom the rule applies or the IdentityReference
        131487 # Set the actually rights of access or the FileSystemRights (Read\Write in this case; check out: https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemrights has a list of what they do if you're interested)
        'Allow' # Set if this is Allowed or Denied behavior or the AccessControlType
    )
    $acl.SetAccessRule($fileSystemAccessRule) # Add the rule to the list of current rules
    $acl | Set-Acl -LiteralPath $Script:rootPath # Apply all those rules to the directory
    Add-TaskToDisplay "Set Directory Permissions"
    Clear-Variable acl,fileSystemAccessRule
}
#endregion
#region Set ACL on Registry
# Permissions on the SAM registry directory are atypical and have to be modified in a different method because of it, most other cases you can still do Get-ACL on a registry object
$registryHKLM            = [Microsoft.Win32.Registry]::LocalMachine # a registry object of HKLM:\
$registryPermissionCheck = [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree # 
$registryRightsChange    = [System.Security.AccessControl.RegistryRights]::ChangePermissions # A specific permission we'll have it check for
$registrySubKey          = $registryHKLM.OpenSubKey("SAM\SAM",$registryPermissionCheck,$registryRightsChange) # Get the registry HKLM:\SAM\SAM
$registrySecurity        = $registrySubKey.GetAccessControl() # Get the security object that already exists
$newRule                 = New-Object System.Security.AccessControl.RegistryAccessRule("BUILTIN\Administrators","FullControl","Allow") # Registry Access Rule for Admins to have Full Control
$registrySecurity.ResetAccessRule($newRule) # Modify existing rule with new one

if(! $Script:RestrictPassword){
    $newRule = New-Object System.Security.AccessControl.RegistryAccessRule($Script:userData.UserName,"ReadKey",[System.Security.AccessControl.InheritanceFlags]::ContainerInherit,"None","Allow") # Registry Access Rule for Child to Read
    $registrySecurity.AddAccessRule($newRule) # Since this rule doesn't already exist, we have to add it to the list
}

$registrySubKey.SetAccessControl($registrySecurity) # Apply the modified rule to the registry object
if(!([bool](Get-ACL "HKLM:\SAM\SAM"))){ Add-TaskToDisplay "Set Registry Permissions" -Failed -Reason "Registry Permissions Inaccessible" }
Clear-Variable registryHKLM,registryPermissionCheck,registryRightsChange,registrySubKey,registrySecurity,newRule
#endregion
#endregion

#region Find RID (Relative ID)
$potentialRIDs = Get-ChildItem 'HKLM:\SAM\SAM\Domains\Account\Users' -Exclude Names # This is where account information is stored in the registry
foreach($potentialRID in $potentialRIDs){
    $value = ($potentialRID.GetValue('V') | Where-Object { $_ -gt 0 } | ForEach-Object { [char]$_ }) -join '' # Converts the Value of the Registry "V" (Yes, really) into a slightly more readable value
    if($value -match $Script:userData.UserName){
        $Script:userData.RID = $potentialRID.PSChildName # This is not the name of your child but a PowerShell child object's Name
        break # Save a nanosecond and break out of loop early
    } # There will be a lot of gibberish inside the value, this checks if the account name is inside of it
}
if(!($userData.RID)){ Add-TaskToDisplay -NewTask "Find Account RID" -Failed -Reason "No Account Found in Registry" } # If the script is unable to find the RID, will stop running, I couldn't get to this with testing but you never know...
Add-TaskToDisplay -NewTask "Find Account RID"
Export-Csv -InputObject $Script:userData -LiteralPath $Script:userFilePath -Delimiter $Script:delimiter
Add-TaskToDisplay -NewTask "Export User Data"

#region Update ACL on Registry Part 2, Electric Boogaloo
if(! $Script:RestrictPassword){
    $acl = Get-Acl "HKLM:\SAM\SAM\Domains\Account\Users\$($Script:userData.RID)" # Get ACL deeper down the Registry Path
    $newRule = New-Object System.Security.AccessControl.RegistryAccessRule(($Script:userData.UserName),"SetValue","Allow") # Write permissions to the key where their password hint is stored
    $acl.AddAccessRule($newRule) # This is adding because it's an implicit permission rather than an inherited one
    $acl | Set-Acl "HKLM:\SAM\SAM\Domains\Account\Users\$($Script:userData.RID)" # As admins, you or the service account will have access already
    Add-TaskToDisplay "Set ACL on Registry RID"
}
#endregion
Clear-Variable potentialRIDs,value
#endregion

#region Prepare CSV
$userChoice = $Host.UI.PromptForChoice("Prepared Sheet", "Do you have a CSV of Questions and Answers already?", [System.Management.Automation.Host.ChoiceDescription[]]((New-Object System.Management.Automation.Host.ChoiceDescription '&Yes'), (New-Object System.Management.Automation.Host.ChoiceDescription '&No')), 1) # Prompt user for pre-prepared CSV

switch ($userChoice){
    -1 {
        Add-TaskToDisplay -NewTask 'Create Q&A CSV' -Failed -Reason "" # User cancelled but not terminating as may supply later
        NoCSVProvided
    } # User cancelled
    
    0 {
        #region Open File Dialog
        Add-Type -AssemblyName System.Windows.Forms # This should be there but best to make sure!
        $filePathWindow = New-Object System.Windows.Forms.OpenFileDialog # This is the window object used for selecting files
        $filePathWindow.Filter = "CSV|*.csv|Speadsheet|*.xlsx?" # Users can select csv,xls,xlsx files
        $okayOrCancel = $filePathWindow.ShowDialog() # Show window for user to select file
        if($okayOrCancel -eq [System.Windows.Forms.DialogResult]::Cancel){
            Add-TaskToDisplay -NewTask 'Create Q&A CSV' -Failed -Reason "" # User cancelled but not terminating as may supply later
            NoCSVProvided    
        } # User cancelled
        #endregion

        #region Import Prearranged File
        if($filePathWindow.FileName -match '.+\.csv$'){
            $csv = Import-Csv -LiteralPath $filePathWindow.FileName # Get csv in array object
            $headers = Get-Member -InputObject $csv | Where-Object -Property MemberType -EQ 'NoteProperty' | Select-Object -ExpandProperty Name # Pull headers and assume first is question, and second is answers
            
            $csv | ForEach-Object { Out-File -LiteralPath $quesitonFilePath -Append -InputObject (@($_.$headers[0],$_.$headers[1],0) -join $Script:delimiter) } # Export Q&A item to desired format
        } # If user selects a CSV
        else{
            $excelWB = New-Object -comobject excel.application # Object for storing Excel's data
            $excelWB.Visible = $false # We don't need it flashing across the screen so we'll hide it
            $workbook = $excelWB.Workbooks.Open($filePathWindow.FileName) # Actually open the file
            for ($i = 1; $i -gt 0; $i++){
                Write-Host "Adding Question $i"
                $question = $workbook.ActiveSheet.Cells.Item($i,1).Value() # Question should be in the first column
                $answer   = $workbook.ActiveSheet.Cells.Item($i,2).Value() # Answer should be in the second column
                if($null -eq $question){ break } # Break if no more questions
                Out-File -LiteralPath $quesitonFilePath -Append -InputObject (@($question,$answer,0) -join $Script:delimiter) # Export Q&A item to desired format
            }
            $excelWB.Quit() # Close the file so it's not open in the background
        } # If user selected a Excel sheet
        #endregion
    } # Yes
    
    Default { NoCSVProvided } # No
}

$qaPull = Import-Csv -LiteralPath $Script:quesitonFilePath -Delimiter $Script:delimiter # Pull the QA sheet
$qaCount = $qaPull.Count # Get the number of QAs available

#region SPLAT!
$splat = New-Object "System.Collections.Generic.Dictionary[System.String,System.Object]" # Splatting is the greatest thing ever
$splat.Add("NewTask","SupplyQAs: $qaCount") # You pass the properties you want to give to a function
if($qaCount -eq 0){
    $splat.Add('Failed',$true) # and can apply logic
    $splat.Add('Reason','') # as well as reuse the splat when you need to make the call a thousand times with little change to the parameters
}
Add-TaskToDisplay @splat
$splat.NewTask = "Update User Password and Hint" # I don't have to update Failed or Reason since it's still there from earlier
if($qaCount -gt 0){ Update-UserPasswordAndHint -Hint $qaPull.Questions[0] -NewPassword $qaPull.Answers[0] -RID $Script:userData.RID -UserName $Script:userData.UserName } # Setting the account's password and password hint
Add-TaskToDisplay @splat
#endregion

Clear-Variable splat,userChoice,qaCount,filePathWindow,okayOrCancel,headers,csv,excelWB,workbook # Most of these won't actually "live" past this point as they're out of scope but it helps me personally remember what I've used

#endregion

#region Create Scheduled Task
$action = New-ScheduledTaskAction -Execute powershell.exe -WorkingDirectory "C:\" -Argument "-File `"$Script:rootPath\UpdateChallenge.ps1`" -ExecutionPolicy Bypass"
$trigger =  New-ScheduledTaskTrigger -User "$env:COMPUTERNAME\$($userData.UserName)" -AtLogOn

Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $name -Description $Description -TaskPath "\" -ErrorAction SilentlyContinue | Out-Null
Add-TaskToDisplay -NewTask "Create Scheduled Task"
#endregion

#region Closing Out
New-Item $Script:rootPath -ItemType File -Name "Logs.csv" | Out-Null # Creates a log file for any issues the update script encounters
Add-TaskToDisplay -NewTask "Create Log File"
#endregion