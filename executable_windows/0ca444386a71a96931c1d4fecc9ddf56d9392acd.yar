rule Unit78020_Malware_Gen3
{
	meta:
		description = "Detects malware by Chinese APT PLA Unit 78020 - Generic Rule - Chong"
		author = "Florian Roth"
		reference = "http://threatconnect.com/camerashy/?utm_campaign=CameraShy"
		date = "2015-09-24"
		super_rule = 1
		hash1 = "2625a0d91d3cdbbc7c4a450c91e028e3609ff96c4f2a5a310ae20f73e1bc32ac"
		hash2 = "5c62b1d16e6180f22a0cb59c99a7743f44cb4a41e4e090b9733d1fb687c8efa2"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "GET http://%ws:%d/%d%s%dHTTP/1.1" fullword ascii
		$x2 = "POST http://%ws:%d/%d%s%dHTTP/1.1" fullword ascii
		$x3 = "J:\\chong\\" ascii
		$s1 = "User-Agent: Netscape" fullword ascii
		$s2 = "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-EN; rv:1.7.12) Gecko/20100719 Firefox/1.0.7" fullword ascii
		$s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\explorer\\User Shell Folders" fullword wide
		$s4 = "J:\\chong\\nod\\Release\\SslMM.exe" fullword ascii
		$s5 = "MM.exe" fullword ascii
		$s6 = "network.proxy.ssl" fullword wide
		$s7 = "PeekNamePipe" fullword ascii
		$s8 = "Host: %ws:%d" fullword ascii
		$s9 = "GET %dHTTP/1.1" fullword ascii
		$s10 = "SCHANNEL.DLL" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 1 of ($x*)) or 4 of ($s*)
}
