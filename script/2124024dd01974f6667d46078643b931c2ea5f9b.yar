rule Empire_KeePassConfig
{
	meta:
		description = "Detects Empire component - file KeePassConfig.ps1"
		author = "Florian Roth"
		reference = "https://github.com/adaptivethreat/Empire"
		date = "2016-11-05"
		hash1 = "5a76e642357792bb4270114d7cd76ce45ba24b0d741f5c6b916aeebd45cff2b3"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "$UserMasterKeyFiles = @(, $(Get-ChildItem -Path $UserMasterKeyFolder -Force | Select-Object -ExpandProperty FullName) )" fullword ascii

	condition:
		( uint16(0)==0x7223 and filesize <80KB and 1 of them ) or all of them
}
