import "pe"

rule MALWARE_Win_DLAgent08
{
	meta:
		author = "ditekSHen"
		description = "Detects known downloader agent downloading encoded binaries in patches"
		snort2_sid = "920122"
		snort3_sid = "920119"
		os = "windows"
		filetype = "executable"

	strings:
		$pat = /\/base\/[A-F0-9]{32}\.html/ ascii wide

	condition:
		uint16(0)==0x5a4d and $pat and #pat>1
}
