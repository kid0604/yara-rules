import "pe"

rule MALWARE_Win_KaraganyKeylogger
{
	meta:
		author = "ditekSHen"
		description = "Detects Karagany/xFrost keylogger plugin"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "__klg__" fullword wide
		$s2 = "__klgkillsoft__" fullword wide
		$s3 = "CLIPBOARD_PASTE" wide
		$s4 = "%s\\k%d.txt" wide
		$s5 = "\\Update\\Tmp" wide

	condition:
		uint16(0)==0x5a4d and 4 of them
}
