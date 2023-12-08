rule Empire_Invoke_Mimikatz_Gen
{
	meta:
		description = "Detects Empire component - file Invoke-Mimikatz.ps1"
		author = "Florian Roth"
		reference = "https://github.com/adaptivethreat/Empire"
		date = "2016-11-05"
		hash1 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "= \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQ" ascii
		$s2 = "Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs)" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <4000KB and 1 of them ) or all of them
}
