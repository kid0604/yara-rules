import "pe"

rule UPX290LZMADelphistubMarkusOberhumerLaszloMolnarJohnReiser
{
	meta:
		author = "malware-lu"
		description = "Detects UPX compressed Delphi executables using the LZMA compression method"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 BE [4] 8D BE [4] C7 87 [8] 57 83 CD FF 89 E5 8D 9C 24 [4] 31 C0 50 39 DC 75 FB 46 46 53 68 [4] 57 83 C3 04 53 68 [4] 56 83 C3 04 }

	condition:
		$a0 at pe.entry_point
}
