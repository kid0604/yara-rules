rule Codoso_Gh0st_1
{
	meta:
		description = "Detects Codoso APT Gh0st Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		super_rule = 1
		hash1 = "5402c785037614d09ad41e41e11093635455b53afd55aa054a09a84274725841"
		hash2 = "7dc7cec2c3f7e56499175691f64060ebd955813002d4db780e68a8f6e7d0a8f8"
		hash3 = "d7004910a87c90ade7e5ff6169f2b866ece667d2feebed6f0ec856fb838d2297"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "cmd.exe /c ping 127.0.0.1 && ping 127.0.0.1 && sc start %s && ping 127.0.0.1 && sc start %s" fullword ascii
		$x2 = "rundll32.exe \"%s\", RunMeByDLL32" fullword ascii
		$x3 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" fullword wide
		$x4 = "\\\\.\\keymmdrv1" fullword ascii
		$s1 = "spideragent.exe" fullword ascii
		$s2 = "AVGIDSAgent.exe" fullword ascii
		$s3 = "kavsvc.exe" fullword ascii
		$s4 = "mspaint.exe" fullword ascii
		$s5 = "kav.exe" fullword ascii
		$s6 = "avp.exe" fullword ascii
		$s7 = "NAV.exe" fullword ascii
		$c1 = "Elevation:Administrator!new:" wide
		$c2 = "Global\\RUNDLL32EXITEVENT_NAME{12845-8654-543}" fullword ascii
		$c3 = "\\sysprep\\sysprep.exe" wide
		$c4 = "\\sysprep\\CRYPTBASE.dll" wide
		$c5 = "Global\\TERMINATEEVENT_NAME{12845-8654-542}" fullword ascii
		$c6 = "ConsentPromptBehaviorAdmin" fullword ascii
		$c7 = "\\sysprep" wide
		$c8 = "Global\\UN{5FFC0C8B-8BE5-49d5-B9F2-BCDC8976EE10}" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and (4 of ($s*) or 4 of ($c*)) or 1 of ($x*) or 6 of ($c*)
}
