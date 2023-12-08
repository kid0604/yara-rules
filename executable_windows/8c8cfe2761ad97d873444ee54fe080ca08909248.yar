rule HttpBrowser_RAT_dropper_Gen1
{
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Dropper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 70
		hash1 = "808de72f1eae29e3c1b2c32be1b84c5064865a235866edf5e790d2a7ba709907"
		hash2 = "f6f966d605c5e79de462a65df437ddfca0ad4eb5faba94fc875aba51a4b894a7"
		hash3 = "f424965a35477d822bbadb821125995616dc980d3d4f94a68c87d0cd9b291df9"
		hash4 = "01441546fbd20487cb2525a0e34e635eff2abe5c3afc131c7182113220f02753"
		hash5 = "8cd8159f6e4689f572e2087394452e80e62297af02ca55fe221fe5d7570ad47b"
		hash6 = "10de38419c9a02b80ab7bf2f1f1f15f57dbb0fbc9df14b9171dc93879c5a0c53"
		hash7 = "c2fa67e970d00279cec341f71577953d49e10fe497dae4f298c2e9abdd3a48cc"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "1001=cmd.exe" fullword ascii
		$x2 = "1003=ShellExecuteA" fullword ascii
		$x3 = "1002=/c del /q %s" fullword ascii
		$x4 = "1004=SetThreadPriority" fullword ascii
		$op0 = { e8 71 11 00 00 83 c4 10 ff 4d e4 8b f0 78 07 8b }
		$op1 = { e8 85 34 00 00 59 59 8b 86 b4 }
		$op2 = { 8b 45 0c 83 38 00 0f 84 97 }
		$op3 = { 8b 45 0c 83 38 00 0f 84 98 }
		$op4 = { 89 7e 0c ff 15 a0 50 40 00 59 8b d8 6a 20 59 8d }
		$op5 = { 56 8d 85 cd fc ff ff 53 50 88 9d cc fc ff ff e8 }

	condition:
		uint16(0)==0x5a4d and filesize <400KB and all of ($x*) and 1 of ($op*)
}
