import "pe"

rule MALWARE_Win_KaraganyCore
{
	meta:
		author = "ditekSHen"
		description = "Detects Karagany/xFrost core plugin"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "127.0.0.1" fullword ascii
		$s2 = "port" fullword ascii
		$s3 = "C:\\Windows\\System32\\Kernel32.dll" fullword ascii
		$s4 = "kernel32.dll" fullword ascii
		$s5 = "http" ascii
		$s6 = "Move" fullword ascii
		$s7 = "<supportedOS Id=\"{" ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
