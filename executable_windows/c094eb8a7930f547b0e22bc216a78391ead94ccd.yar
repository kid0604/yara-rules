import "pe"

rule Disclosed_0day_POCs_payload_MSI
{
	meta:
		description = "Detects POC code from disclosed 0day hacktool set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed 0day Repos"
		date = "2017-07-07"
		modified = "2022-12-21"
		hash1 = "a7c498a95850e186b7749a96004a98598f45faac2de9b93354ac93e627508a87"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "WShell32.dll" fullword wide
		$s2 = "Target empty, so account name translation begins on the local system." fullword wide
		$s3 = "\\custact\\x86\\AICustAct.pdb" ascii

	condition:
		( uint16(0)==0xcfd0 and filesize <1000KB and all of them )
}
