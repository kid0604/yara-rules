import "pe"

rule MALWARE_Win_LOLKEK
{
	meta:
		author = "ditekShen"
		description = "Detects LOLKEK / GlobeImposter ransowmare"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "$Recycle.bin" fullword wide
		$s2 = "\\\\?\\%c:" fullword wide
		$s3 = ".MMM" fullword wide
		$s4 = "ReadMe.txt" fullword wide
		$s5 = "select * from Win32_ShadowCopy" fullword wide
		$s6 = "Win32_ShadowCopy.ID='%s'" fullword wide
		$s7 = "W3CRYPTO LOCKER" ascii
		$s8 = "http://mmcb" ascii
		$s9 = "yip.su/2QstD5" ascii
		$s10 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AddInProcess32.exe" ascii

	condition:
		uint16(0)==0x5a4d and 7 of them
}
