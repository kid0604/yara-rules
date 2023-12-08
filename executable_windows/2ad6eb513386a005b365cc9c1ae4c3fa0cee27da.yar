rule Waterbear_4_Jun17
{
	meta:
		description = "Detects malware from Operation Waterbear"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/L9g9eR"
		date = "2017-06-23"
		hash1 = "2e9cb7cadb3478edc9ef714ca4ddebb45e99d35386480e12792950f8a7a766e1"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;)" fullword ascii
		$s1 = "Wininet.dll InternetOpenA InternetConnectA HttpOpenRequestA HttpSendRequestA HttpQueryInfoA InternetReadFile InternetCloseHandle" fullword ascii
		$s2 = "read from pipe:%s" fullword ascii
		$s3 = "delete pipe" fullword ascii
		$s4 = "cmdcommand:%s" fullword ascii
		$s5 = "%s /c del %s" fullword ascii
		$s6 = "10.0.0.250" fullword ascii
		$s7 = "Vista/2008" fullword ascii
		$s8 = "%02X%02X%02X%02X%02X%02X%04X" fullword ascii
		$s9 = "UNKOWN" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 3 of them )
}
