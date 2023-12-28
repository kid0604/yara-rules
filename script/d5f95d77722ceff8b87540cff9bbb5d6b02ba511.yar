rule APT10_ChChes_powershell
{
	meta:
		description = "ChChes dropper PowerShell based PowerSploit"
		author = "JPCERT/CC Incident Response Group"
		hash = "9fbd69da93fbe0e8f57df3161db0b932d01b6593da86222fabef2be31899156d"
		os = "windows"
		filetype = "script"

	strings:
		$v1a = "Invoke-Shellcode"
		$v1b = "Invoke-shCdpot"
		$v1c = "invoke-ExEDoc"

	condition:
		$v1c and ($v1a or $v1b)
}
