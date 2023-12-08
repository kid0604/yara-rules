rule INDICATOR_TOOL_EXP_SeriousSAM02
{
	meta:
		author = "ditekSHen"
		description = "Detect tool variants potentially exploiting SeriousSAM / HiveNightmare CVE-2021-36934"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy" fullword wide
		$s2 = /(Windows\\System32\\config)?\\(SAM|SECURITY|SYSTEM)/ ascii wide
		$s3 = /(SAM|SECURITY|SYSTEM)-%s/ fullword wide
		$s4 = /: (SAM|SECURITY|SYSTEM) hive from/ wide
		$v1 = "VolumeShadowCopy" ascii wide
		$v2 = "GLOBALROOT" ascii wide
		$v3 = "Device" ascii wide
		$n1 = "Block Level Backup Engine Service EXE" ascii wide
		$n2 = "|TaskID=%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X" wide
		$n3 = "[traceprovider-trace] Failed: %ws: %#010x" wide
		$n4 = "base\\stor\\blb\\engine\\usn\\base\\lib\\usnjournalhelper.cpp" wide

	condition:
		uint16(0)==0x5a4d and not any of ($n*) and ( all of ($s*) or ( all of ($v*) and 2 of ($s*)) or ( all of ($v*) and #s2>2))
}
