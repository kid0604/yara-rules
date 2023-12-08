import "pe"

rule SimplePackV11XV12XMethod1bagie
{
	meta:
		author = "malware-lu"
		description = "Detects SimplePack v1.1X and v1.2X using Method 1"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B FA BD [4] 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 0F B7 76 06 4E 8B 47 10 09 C0 }

	condition:
		$a0 at pe.entry_point
}
