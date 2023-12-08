rule FourElementSword_T9000
{
	meta:
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "5f3d0a319ecc875cc64a40a34d2283cb329abcf79ad02f487fbfd6bef153943c"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "D:\\WORK\\T9000\\" ascii
		$x2 = "%s\\temp\\HHHH.dat" fullword wide
		$s1 = "Elevate.dll" fullword wide
		$s2 = "ResN32.dll" fullword wide
		$s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword wide
		$s4 = "igfxtray.exe" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and 1 of ($x*)) or ( all of them )
}
