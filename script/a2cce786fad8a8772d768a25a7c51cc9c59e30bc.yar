rule Empire_Invoke_PsExec
{
	meta:
		description = "Detects Empire component - file Invoke-PsExec.ps1"
		author = "Florian Roth"
		reference = "https://github.com/adaptivethreat/Empire"
		date = "2016-11-05"
		hash1 = "0218be4323959fc6379489a6a5e030bb9f1de672326e5e5b8844ab5cedfdcf88"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "Invoke-PsExecCmd" fullword ascii
		$s2 = "\"[*] Executing service .EXE" fullword ascii
		$s3 = "$cmd = \"%COMSPEC% /C echo $Command ^> %systemroot%\\Temp\\" ascii

	condition:
		( uint16(0)==0x7566 and filesize <50KB and 1 of them ) or all of them
}
