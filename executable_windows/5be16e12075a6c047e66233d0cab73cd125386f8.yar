rule HttpBrowser_RAT_dropper_Gen2
{
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Dropper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 70
		hash1 = "c57c5a2c322af2835ae136b75283eaaeeaa6aa911340470182a9983ae47b8992"
		hash2 = "dfa984174268a9f364d856fd47cfaca75804640f849624d69d81fcaca2b57166"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "navlu.dll.urlUT" fullword ascii
		$s2 = "VPDN_LU.exeUT" fullword ascii
		$s3 = "pnipcn.dllUT" fullword ascii
		$s4 = "\\ssonsvr.exe" ascii
		$s5 = "/c del /q %s" fullword ascii
		$s6 = "\\setup.exe" ascii
		$s7 = "msi.dllUT" fullword ascii
		$op0 = { 8b 45 0c 83 38 00 0f 84 98 }
		$op1 = { e8 dd 07 00 00 ff 35 d8 fb 40 00 8b 35 7c a0 40 }
		$op2 = { 83 fb 08 75 2c 8b 0d f8 af 40 00 89 4d dc 8b 0d }
		$op3 = { c7 43 18 8c 69 40 00 e9 da 01 00 00 83 7d f0 00 }
		$op4 = { 6a 01 e9 7c f8 ff ff bf 1a 40 00 96 1b 40 00 01 }

	condition:
		uint16(0)==0x5a4d and filesize <400KB and 3 of ($s*) and 1 of ($op*)
}
