import "pe"

rule MALWARE_Win_FYAnti
{
	meta:
		author = "ditekSHen"
		description = "Hunt for FYAnti third-stage loader DLLs"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and pe.is_dll() and pe.exports("FuckYouAnti")
}
