import "pe"

rule MALWARE_Win_KaraganyScreenUtil
{
	meta:
		author = "ditekSHen"
		description = "Detects Karagany/xFrost ScreenUtil module"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "__pic__" ascii wide
		$s2 = "__pickill__" ascii wide
		$s3 = "\\picture.png" fullword wide
		$s4 = "%d.jpg" wide
		$s5 = "\\Update\\Tmp" wide

	condition:
		uint16(0)==0x5a4d and 4 of them
}
