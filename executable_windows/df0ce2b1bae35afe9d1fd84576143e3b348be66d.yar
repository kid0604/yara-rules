import "pe"

rule RCryptor15Vaska
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of RCryptor15Vaska malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 2C 24 4F 68 [4] FF 54 24 04 83 44 24 04 4F B8 [4] 3D [4] 74 06 80 30 [2] EB F3 B8 [4] 3D [4] 74 06 80 30 ?? 40 EB F3 }

	condition:
		$a0 at pe.entry_point
}
