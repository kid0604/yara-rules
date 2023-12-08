import "pe"

rule MALWARE_Win_HyperBro02
{
	meta:
		author = "ditekSHen"
		description = "Detects HyperBro IronTiger / LuckyMouse / APT27 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\cmd.exe /A" fullword wide
		$s2 = "C:\\windows\\explorer.exe" fullword wide
		$s3 = "\\\\.\\pipe\\testpipe" fullword wide
		$s4 = "Elevation:Administrator!new:{" wide
		$s5 = "log.log" fullword wide
		$s6 = "%s\\%d.exe" fullword wide
		$s7 = ".?AVTPipeProtocol@@" fullword ascii
		$s8 = ".?AVTCaptureMgr@@" fullword ascii
		$s9 = "system-%d" fullword wide
		$s10 = "[test] %02d:%02d:%02d:%03d %s" fullword wide
		$s11 = "\\..\\data.dat" fullword wide
		$s12 = "\\..\\config.ini" fullword wide
		$s13 = { 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00 20 00 2d 00 77 00 6f 00 72 00 6b 00 65 00 72 00 }
		$s14 = { 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00 20 00 2d 00 64 00 61 00 65 00 6d 00 6f 00 6e 00 }
		$cnc1 = "https://%s:%d/ajax" fullword wide
		$cnc2 = "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36" fullword wide
		$cnc3 = "139.180.208.225" fullword wide

	condition:
		uint16(0)==0x5a4d and (7 of ($s*) or (2 of ($cnc*) and 2 of ($s*)))
}
