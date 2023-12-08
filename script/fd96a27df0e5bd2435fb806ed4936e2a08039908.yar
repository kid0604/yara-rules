rule SUSP_Scheduled_Task_BigSize
{
	meta:
		description = "Detects suspiciously big scheduled task XML file as seen in combination with embedded base64 encoded PowerShell code"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-12-06"
		os = "windows"
		filetype = "script"

	strings:
		$a0 = "<Task version=" ascii wide
		$a1 = "xmlns=\"http://schemas.microsoft.com/windows/" ascii wide
		$fp1 = "</Counter><Counter>" wide
		$fp2 = "Office Feature Updates Logon" wide
		$fp3 = "Microsoft Shared" fullword wide

	condition:
		uint16(0)==0xfeff and filesize >20KB and all of ($a*) and not 1 of ($fp*)
}
