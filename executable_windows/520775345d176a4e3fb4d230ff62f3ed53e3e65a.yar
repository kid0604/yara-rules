import "pe"

rule MALWARE_Win_FloodFix
{
	meta:
		author = "ditekSHen"
		description = "Detects FloodFix"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and pe.is_dll() and (pe.exports("FloodFix") or pe.exports("FloodFix2")) and pe.exports("crc32")
}
