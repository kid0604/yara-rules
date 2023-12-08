rule INDICATOR_TOOL_UAC_NSISUAC
{
	meta:
		author = "ditekSHen"
		description = "Detects NSIS UAC plugin"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "HideCurrUserOpt" fullword wide
		$s2 = "/UAC:%X /NCRC%s" fullword wide
		$s3 = "2MyRunAsStrings" fullword wide
		$s4 = "CheckElevationEnabled" fullword ascii
		$s5 = "UAC.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
