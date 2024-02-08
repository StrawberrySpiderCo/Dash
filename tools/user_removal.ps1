#### Written and tested by Chris 12-18-23 ####
 
#### PROMPT FOR THE SAMACCOUNT NAME OF THE TERMINATED USER ####
$terminatedUser = $args[0]
#### MOVE THEM TO TERMINATED OU ####
Get-ADUser -Identity $terminateduser | Move-ADObject -TargetPath "OU=TERMINATED,OU=DISABLED USERS,OU=CSV-NEW,DC=csv-dom,DC=local"
 
                    ##### REMOVE FROM ALL GROUPS ####
$userInfo = get-aduser -Identity $terminateduser -properties MemberOf
Foreach ($group in $userInfo.MemberOf) { Remove-ADGroupMember -Identity $group -Members $terminateduser -Confirm:$false
}
 
                    #### SET ATTRIBUTES TO HIDE FROM GAL AND CLEAR MANAGER ####
Set-ADUser -Identity $terminateduser -Replace @{MailNickname="$terminateduser"}
Set-ADUser -Identity $terminateduser -Replace @{msExchHideFromAddressLists=$true}
Set-AdUser -Identity $terminateduser -clear manager
 
                    #### DISABLE THE ACCOUNT ####
Disable-ADAccount -Identity $terminatedUser
 
                    #### CONVERT TO SHARED MAILBOX ####
$Credential = Get-Credential
Connect-ExchangeOnline -Credential $Credential
Set-Mailbox -Identity "$terminateduser@clinicasierravista.org" -Type Shared
 
                    #### REMOVE FROM CLOUD GROUPS AND REVOKE SESSIONS ####
                                #### AIN"T WORKING YET ####
#$Credential = Get-Credential
#Connect-AzureAD -Credential $Credential
#$AZUserID = Get-azureaduser -ObjectID "$terminateduser@clinicasierravista.org"
#Revoke-AzureADUserAllRefreshToken -ObjectId "$AZUserID"
#$AZGroups = Get-AzureADUserMembership  -ObjectId $AZuserID
#foreach($Group in $AZGroups.ObjectId){
#Remove-AzureADGroupMember -ObjectId $Group -MemberId $AZuserID
#}