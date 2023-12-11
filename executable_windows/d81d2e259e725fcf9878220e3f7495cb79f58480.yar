import "pe"

rule SimplePack111Method2NTbagieTMX
{
	meta:
		author = "malware-lu"
		description = "Detects a simple packer method 2 used by NTbagieTMX malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 89 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 }

	condition:
		$a0 at pe.entry_point
}
