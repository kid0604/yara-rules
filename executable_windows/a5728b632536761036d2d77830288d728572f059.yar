import "pe"

rule MALWARE_Win_KaraganyListrix
{
	meta:
		author = "ditekSHen"
		description = "Detects Karagany/xFrost Listrix module"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\Update\\Tmp\\" wide
		$s2 = "*pass*.*" fullword wide
		$s3 = ">> NUL" wide
		$s4 = "%02d.%02d.%04d %02d:%02d" wide
		$s5 = "/c del" wide

	condition:
		uint16(0)==0x5a4d and 4 of them
}
