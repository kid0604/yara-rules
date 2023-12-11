import "pe"

rule HKTL_NET_GUID_privilege_escalation_awesome_scripts_suite_alt_1
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "1928358e-a64b-493f-a741-ae8e3d029374" ascii wide
		$typelibguid0up = "1928358E-A64B-493F-A741-AE8E3D029374" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
