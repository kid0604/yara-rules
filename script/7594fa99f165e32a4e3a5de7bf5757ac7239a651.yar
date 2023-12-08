rule Msfpayloads_msf_cmd
{
	meta:
		description = "Metasploit Payloads - file msf-cmd.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "9f41932afc9b6b4938ee7a2559067f4df34a5c8eae73558a3959dd677cb5867f"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -e" ascii

	condition:
		all of them
}
