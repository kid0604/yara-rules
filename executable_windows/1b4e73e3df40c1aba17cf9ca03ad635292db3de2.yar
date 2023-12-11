import "hash"

rule Gandcrab4
{
	meta:
		description = "Detect the risk of GandCrab Rule 4"
		os = "windows"
		filetype = "executable"

	strings:
		$hex1 = { 55 8B EC 83 EC ?? 53 56 ?? 3? ?? ?? ?? ?? 5? ?? }
		$hex2 = { 8B 45 08 33 45 FC 89 ?1 ?C ?? ?? ?? ?? ?8 ?? ?? }

	condition:
		all of them and uint16(0)==0x5A4D and filesize <100KB
}
