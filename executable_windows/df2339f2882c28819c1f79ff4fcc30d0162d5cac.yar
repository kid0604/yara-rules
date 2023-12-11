import "pe"

rule MALWARE_Win_FujinamaRAT
{
	meta:
		author = "ditekSHen"
		description = "Detects FujinamaRAT"
		snort2_sid = "920124"
		snort3_sid = "920121"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "GetAsyncKeyState" fullword ascii
		$s2 = "HTTP/1.0" fullword wide
		$s3 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)" fullword wide
		$s4 = "frmMain" fullword ascii
		$s5 = "G<=>?@ABGGGGGGGGGGGGGGGGGGGGGGGGGGCDEF" fullword ascii
		$s6 = "VBA6.DLL" fullword ascii
		$s7 = "t_save" fullword ascii

	condition:
		uint16(0)==0x5a4d and 6 of them
}
