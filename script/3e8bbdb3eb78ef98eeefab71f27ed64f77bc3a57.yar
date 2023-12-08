rule Empire_Invoke_SSHCommand
{
	meta:
		description = "Detects Empire component - file Invoke-SSHCommand.ps1"
		author = "Florian Roth"
		reference = "https://github.com/adaptivethreat/Empire"
		date = "2016-11-05"
		hash1 = "cbaf086b14d5bb6a756cbda42943d4d7ef97f8277164ce1f7dd0a1843e9aa242"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s1 = "$Base64 = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAA" ascii
		$s2 = "Invoke-SSHCommand -ip 192.168.1.100 -Username root -Password test -Command \"id\"" fullword ascii
		$s3 = "Write-Verbose \"[*] Error loading dll\"" fullword ascii

	condition:
		( uint16(0)==0x660a and filesize <2000KB and 1 of them ) or all of them
}
