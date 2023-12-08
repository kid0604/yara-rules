rule Msfpayloads_msf_psh
{
	meta:
		description = "Metasploit Payloads - file msf-psh.vba"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "5cc6c7f1aa75df8979be4a16e36cece40340c6e192ce527771bdd6463253e46f"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "powershell.exe -nop -w hidden -e" ascii
		$s2 = "Call Shell(" ascii
		$s3 = "Sub Workbook_Open()" fullword ascii

	condition:
		all of them
}
