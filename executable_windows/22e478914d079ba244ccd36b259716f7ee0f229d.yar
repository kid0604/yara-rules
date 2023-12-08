import "pe"

rule INDICATOR_EXE_Packed_BoxedApp
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with BoxedApp"
		snort2_sid = "930037-930042"
		snort3_sid = "930013-930014"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "BoxedAppSDK_HookFunction" fullword ascii
		$s2 = "BoxedAppSDK_StaticLib.cpp" ascii
		$s3 = "embedding BoxedApp into child processes: %s" ascii
		$s4 = "GetCommandLineA preparing to intercept" ascii

	condition:
		uint16(0)==0x5a4d and 2 of them or for any i in (0..pe.number_of_sections) : ((pe.sections[i].name contains ".bxpck"))
}
