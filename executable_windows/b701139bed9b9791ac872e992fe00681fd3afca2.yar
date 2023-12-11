rule INDICATOR_TOOL_EXP_SeriousSAM01
{
	meta:
		author = "ditekSHen"
		description = "Detect tool variants potentially exploiting SeriousSAM / HiveNightmare CVE-2021-36934"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "VolumeShadowCopy" fullword wide
		$s2 = "\\\\?\\GLOBALROOT\\Device\\" fullword wide
		$s3 = "{0}\\{1}$:aad3b435b51404eeaad3b435b51404ee:{2}" fullword wide
		$s4 = "ASPNET_WP_PASSWORD" fullword wide
		$s5 = "<ParseSam>b__" ascii
		$s6 = "<DumpSecret" ascii
		$s7 = "<ParseSecret" ascii
		$s8 = "LsaSecretBlob" fullword ascii
		$s9 = "systemHive" fullword ascii
		$s10 = "ImportHiveDump" fullword ascii
		$s11 = "FindShadowVolumes" fullword ascii
		$s12 = "GetBootKey" fullword ascii
		$r1 = "[*] SAM" wide
		$r2 = "[*] SYSTEM" wide
		$r3 = "[*] SECURITY" wide

	condition:
		uint16(0)==0x5a4d and (6 of ($s*) or ( all of ($r*) and 3 of ($s*)))
}
