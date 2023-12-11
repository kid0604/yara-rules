rule onimiki
{
	meta:
		description = "Linux/Onimiki malicious DNS server"
		malware = "Linux/Onimiki"
		operation = "Windigo"
		author = "Olivier Bilodeau <bilodeau@eset.com>"
		created = "2014-02-06"
		reference = "http://www.welivesecurity.com/wp-content/uploads/2014/03/operation_windigo.pdf"
		contact = "windigo@eset.sk"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		os = "linux"
		filetype = "executable"

	strings:
		$a1 = {43 0F B6 74 2A 0E 43 0F  B6 0C 2A 8D 7C 3D 00 8D}
		$a2 = {74 35 00 8D 4C 0D 00 89  F8 41 F7 E3 89 F8 29 D0}
		$a3 = {D1 E8 01 C2 89 F0 C1 EA  04 44 8D 0C 92 46 8D 0C}
		$a4 = {8A 41 F7 E3 89 F0 44 29  CF 29 D0 D1 E8 01 C2 89}
		$a5 = {C8 C1 EA 04 44 8D 04 92  46 8D 04 82 41 F7 E3 89}
		$a6 = {C8 44 29 C6 29 D0 D1 E8  01 C2 C1 EA 04 8D 04 92}
		$a7 = {8D 04 82 29 C1 42 0F B6  04 21 42 88 84 14 C0 01}
		$a8 = {00 00 42 0F B6 04 27 43  88 04 32 42 0F B6 04 26}
		$a9 = {42 88 84 14 A0 01 00 00  49 83 C2 01 49 83 FA 07}

	condition:
		all of them
}
