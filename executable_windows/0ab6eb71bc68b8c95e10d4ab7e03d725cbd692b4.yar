rule GRIZZLY_STEPPE_Malware_2
{
	meta:
		description = "Auto-generated rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/WVflzO"
		date = "2016-12-29"
		hash1 = "9acba7e5f972cdd722541a23ff314ea81ac35d5c0c758eb708fb6e2cc4f598a0"
		hash2 = "55058d3427ce932d8efcbe54dccf97c9a8d1e85c767814e34f4b2b6a6b305641"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "GoogleCrashReport.dll" fullword ascii
		$s1 = "CrashErrors" fullword ascii
		$s2 = "CrashSend" fullword ascii
		$s3 = "CrashAddData" fullword ascii
		$s4 = "CrashCleanup" fullword ascii
		$s5 = "CrashInit" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and $x1) or ( all of them )
}
