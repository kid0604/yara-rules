import "pe"

rule qbot_dll_8734
{
	meta:
		description = "files - qbot.dll"
		author = "TheDFIRReport"
		reference = "QBOT_DLL"
		date = "2021-12-04"
		hash1 = "4d3b10b338912e7e1cbade226a1e344b2b4aebc1aa2297ce495e27b2b0b5c92b"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Execute not supported: %sfField '%s' is not the correct type of calculated field to be used in an aggregate, use an internalcalc" wide
		$s2 = "IDAPI32.DLL" fullword ascii
		$s3 = "ResetUsageDataActnExecute" fullword ascii
		$s4 = "idapi32.DLL" fullword ascii
		$s5 = "ShowHintsActnExecute" fullword ascii
		$s6 = "OnExecute@iG" fullword ascii
		$s7 = "OnExecutexnD" fullword ascii
		$s8 = "ShowShortCutsInTipsActnExecute" fullword ascii
		$s9 = "ResetActnExecute " fullword ascii
		$s10 = "RecentlyUsedActnExecute" fullword ascii
		$s11 = "LargeIconsActnExecute" fullword ascii
		$s12 = "ResetActnExecute" fullword ascii
		$s13 = "OnExecute<" fullword ascii
		$s14 = "TLOGINDIALOG" fullword wide
		$s15 = "%s%s:\"%s\";" fullword ascii
		$s16 = ":\":&:7:?:C:\\:" fullword ascii
		$s17 = "LoginPrompt" fullword ascii
		$s18 = "TLoginDialog" fullword ascii
		$s19 = "OnLogin" fullword ascii
		$s20 = "Database Login" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and 12 of them
}
