import "pe"

rule TA17_293A_Hacktool_PS_1
{
	meta:
		description = "Auto-generated rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
		date = "2017-10-21"
		hash1 = "72a28efb6e32e653b656ca32ccd44b3111145a695f6f6161965deebbdc437076"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "$HashFormat = '$krb5tgs$23$*ID#124_DISTINGUISHED NAME: CN=fakesvc,OU=Service,OU=Accounts,OU=EnterpriseObjects,DC=asdf,DC=pd,DC=f" ascii
		$x2 = "} | Where-Object {$_.SamAccountName -notmatch 'krbtgt'} | Get-SPNTicket @GetSPNTicketArguments" fullword ascii

	condition:
		( filesize <80KB and 1 of them )
}
