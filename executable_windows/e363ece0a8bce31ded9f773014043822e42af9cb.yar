import "pe"

rule Upack012betaDwing
{
	meta:
		author = "malware-lu"
		description = "Detects the Upack 0.12 beta Dwing malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE 48 01 40 00 AD [3] A5 ?? C0 33 C9 [7] F3 AB [2] 0A [4] AD 50 97 51 ?? 87 F5 58 8D 54 86 5C ?? D5 72 [15] B6 5F FF C1 }

	condition:
		$a0 at pe.entry_point
}
