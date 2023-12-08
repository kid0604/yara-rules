import "pe"

rule CrypKeyV56XDLLKenonicControlsLtd
{
	meta:
		author = "malware-lu"
		description = "Detects CrypKey v5.6.x DLL from Kenonic Controls Ltd"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8B 1D [4] 83 FB 00 75 0A E8 [4] E8 }

	condition:
		$a0 at pe.entry_point
}
