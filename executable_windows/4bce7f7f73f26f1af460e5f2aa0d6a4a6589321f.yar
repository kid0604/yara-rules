rule Waterbear_13_Jun17
{
	meta:
		description = "Detects malware from Operation Waterbear"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/L9g9eR"
		date = "2017-06-23"
		super_rule = 1
		hash1 = "734e5972ab5ac1e9bc5470c666a55e0d2bd57c4e2ea2da11dc9bf56fb2ea6f23"
		hash2 = "8bde3f71575aa0d5f5a095d9d0ea10eceadba38be888e10d3ca3776f7b361fe7"
		hash3 = "c4b3b0a7378bfc3824d4178fd7fb29475c42ab874d69abdfb4898d0bcd4f8ce1"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%WINDIR%\\PCHealth\\HelpCtr\\Binaries\\pchsvc.dll" fullword ascii
		$s2 = "brnew.exe" fullword ascii
		$s3 = "ChangeServiceConfig failed (%d)" fullword ascii
		$s4 = "Proxy %d:%s %d" fullword ascii
		$s5 = "win9807.tmp" fullword ascii
		$s7 = "Service stopped successfully" fullword ascii
		$s8 = "current dns:%s" fullword ascii
		$s9 = "%c%u|%u|%u|%u|%u|" fullword ascii
		$s10 = "[-]send %d: " fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 4 of them )
}
