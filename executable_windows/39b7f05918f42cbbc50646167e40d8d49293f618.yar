import "pe"

rule MALWARE_Win_DllHijacker02
{
	meta:
		author = "ditekSHen"
		description = "Detects ServiceCrt / DllHijacker03 IronTiger / LuckyMouse / APT27 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "ServiceCrtMain" fullword ascii
		$s2 = "mpsvc.dll" fullword ascii
		$o1 = { 84 db 0f 85 4c ff ff ff e8 14 06 00 00 8b f0 83 }
		$o2 = { f7 c1 00 ff ff ff 75 c5 eb 13 0f ba 25 10 20 01 }
		$o3 = { 8d 04 b1 8b d9 89 45 fc 8d 34 b9 a1 18 20 01 10 }
		$o4 = { b0 01 c3 68 b8 2c 01 10 e8 83 ff ff ff c7 04 24 }
		$o5 = { eb 34 66 0f 12 0d 00 fe 00 10 f2 0f 59 c1 ba cc }
		$o6 = { 73 c7 dc 0d 4c ff 00 10 eb bf dd 05 34 ff 00 10 }

	condition:
		uint16(0)==0x5a4d and all of ($s*) and 5 of ($o*)
}
