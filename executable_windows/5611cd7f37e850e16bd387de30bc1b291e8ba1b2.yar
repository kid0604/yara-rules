import "pe"

rule RCryptorV16dVaska
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of RCryptorV16dVaska malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 [4] B8 [4] 90 3D [4] 74 06 80 30 ?? 40 EB F3 B8 [4] 90 3D [4] 74 06 80 30 ?? 40 EB F3 }

	condition:
		$a0 at pe.entry_point
}
