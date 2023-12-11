rule Empire_Get_GPPPassword
{
	meta:
		description = "Detects Empire component - file Get-GPPPassword.ps1"
		author = "Florian Roth"
		reference = "https://github.com/adaptivethreat/Empire"
		date = "2016-11-05"
		hash1 = "55a4519c4f243148a971e4860225532a7ce730b3045bde3928303983ebcc38b0"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "$Base64Decoded = [Convert]::FromBase64String($Cpassword)" fullword ascii
		$s2 = "$XMlFiles += Get-ChildItem -Path \"\\\\$DomainController\\SYSVOL\" -Recurse" ascii
		$s3 = "function Get-DecryptedCpassword {" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <30KB and 1 of them ) or all of them
}
