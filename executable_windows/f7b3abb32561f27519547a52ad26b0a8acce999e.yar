rule Locky_Ransomware_2 : ransom
{
	meta:
		description = "Regla para detectar RANSOM.LOCKY"
		author = "CCN-CERT"
		version = "1.0"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = { 2E 00 6C 00 6F 00 63 00 6B 00 79 00 00 }
		$a2 = { 00 5F 00 4C 00 6F 00 63 00 6B 00 79 00 }
		$a3 = { 5F 00 72 00 65 00 63 00 6F 00 76 00 65 }
		$a4 = { 00 72 00 5F 00 69 00 6E 00 73 00 74 00 }
		$a5 = { 72 00 75 00 63 00 74 00 69 00 6F 00 6E }
		$a6 = { 00 73 00 2E 00 74 00 78 00 74 00 00 }
		$a7 = { 53 6F 66 74 77 61 72 65 5C 4C 6F 63 6B 79 00 }

	condition:
		all of them
}
