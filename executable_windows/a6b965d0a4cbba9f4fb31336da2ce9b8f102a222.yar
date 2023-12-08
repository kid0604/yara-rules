import "pe"

rule PasswordprotectormySMT
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the Password Protector mySMT malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [4] 5D 8B FD 81 [5] 81 [5] 83 [2] 89 [5] 8D [5] 8D [5] 46 80 [2] 74 }

	condition:
		$a0 at pe.entry_point
}
