import "pe"

rule MALWARE_Win_Gaudox
{
	meta:
		author = "ditekshen"
		description = "Detects Gaudox RAT"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "hdr=%s&tid;=%s&cid;=%s&trs;=%i" ascii wide
		$s2 = "\\\\\\\\.\\\\PhysicalDrive%u" ascii wide

	condition:
		uint16(0)==0x5a4d and all of them
}
