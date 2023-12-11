rule Empire_Invoke_CredentialInjection_Invoke_Mimikatz_Gen
{
	meta:
		description = "Detects Empire component - from files Invoke-CredentialInjection.ps1, Invoke-Mimikatz.ps1"
		author = "Florian Roth"
		reference = "https://github.com/adaptivethreat/Empire"
		date = "2016-11-05"
		super_rule = 1
		hash1 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
		hash2 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle" fullword ascii
		$s2 = "$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <4000KB and 1 of them ) or all of them
}
