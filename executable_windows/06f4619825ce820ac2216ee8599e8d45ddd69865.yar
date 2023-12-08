import "pe"

rule CrypKeyV61XDLLCrypKeyCanadaInc
{
	meta:
		author = "malware-lu"
		description = "Detects CrypKey v6.1.x DLL from CrypKey Canada Inc"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 3D [4] 00 75 34 68 [4] E8 }

	condition:
		$a0 at pe.entry_point
}
