import "pe"

rule LocklessIntroPack
{
	meta:
		author = "malware-lu"
		description = "Detects LocklessIntroPack malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 2C E8 [4] 5D 8B C5 81 ED F6 73 [2] 2B 85 [4] 83 E8 06 89 85 }

	condition:
		$a0 at pe.entry_point
}
