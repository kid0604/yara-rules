import "pe"

rule APT_MAL_TinyTurla_Sep21_1
{
	meta:
		author = "Cisco Talos"
		description = "Detects Tiny Turla backdoor DLL"
		reference = "https://blog.talosintelligence.com/2021/09/tinyturla.html"
		hash1 = "030cbd1a51f8583ccfc3fa38a28a5550dc1c84c05d6c0f5eb887d13dedf1da01"
		date = "2021-09-21"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "Title: " fullword wide
		$b = "Hosts" fullword wide
		$c = "Security" fullword wide
		$d = "TimeLong" fullword wide
		$e = "TimeShort" fullword wide
		$f = "MachineGuid" fullword wide
		$g = "POST" fullword wide
		$h = "WinHttpSetOption" fullword ascii
		$i = "WinHttpQueryDataAvailable" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <25KB and all of them
}
