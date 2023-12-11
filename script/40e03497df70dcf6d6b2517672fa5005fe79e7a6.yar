rule Empire_Invoke_MetasploitPayload
{
	meta:
		description = "Detects Empire component - file Invoke-MetasploitPayload.ps1"
		author = "Florian Roth"
		reference = "https://github.com/adaptivethreat/Empire"
		date = "2016-11-05"
		hash1 = "a85ca27537ebeb79601b885b35ddff6431860b5852c6a664d32a321782808c54"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "$ProcessInfo.Arguments=\"-nop -c $DownloadCradle\"" fullword ascii
		$s2 = "$PowershellExe=$env:windir+'\\syswow64\\WindowsPowerShell\\v1.0\\powershell.exe'" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <9KB and 1 of them ) or all of them
}
