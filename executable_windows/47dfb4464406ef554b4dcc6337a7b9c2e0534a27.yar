import "pe"

rule MALWARE_Win_AvosLocker
{
	meta:
		author = "ditekSHen"
		description = "Hunt for AvosLocker ransomware"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "GET_YOUR_FILES_BACK.txt" ascii wide
		$s2 = ".avos" fullword ascii wide

	condition:
		uint16(0)==0x5a4d and all of them
}
