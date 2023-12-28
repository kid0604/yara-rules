rule SteelClover_PowerShell_str
{
	meta:
		description = "PowerShell in SteelClover"
		author = "JPCERT/CC Incident Response Group"
		hash = "05e6f7a4184c9688ccef4dd17ae8ce0fe788df1677c6ba754b37a895a1e430e9"
		os = "windows"
		filetype = "script"

	strings:
		$a1 = "function Add-Encryption" ascii
		$a2 = "function Remove-Encryption" ascii
		$a3 = "Remove-Encryption -FolderPath $env:APPDATA -Password" ascii
		$b1 = "function Install-GnuPg" ascii
		$b2 = "Install-GnuPG -DownloadFolderPath $env:APPDATA" ascii

	condition:
		all of ($a*) or all of ($b*)
}
