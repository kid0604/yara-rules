rule Empire_KeePassConfig_Gen
{
	meta:
		description = "Detects Empire component - from files KeePassConfig.ps1, KeePassConfig.ps1"
		author = "Florian Roth"
		reference = "https://github.com/adaptivethreat/Empire"
		date = "2016-11-05"
		super_rule = 1
		hash2 = "5a76e642357792bb4270114d7cd76ce45ba24b0d741f5c6b916aeebd45cff2b3"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "$KeePassXML = [xml](Get-Content -Path $KeePassXMLPath)" fullword ascii

	condition:
		( uint16(0)==0x7223 and filesize <80KB and 1 of them ) or all of them
}
