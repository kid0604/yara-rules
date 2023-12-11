rule HKTL_NET_GUID_privilege_escalation_awesome_scripts_suite
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite"
		author = "Arnim Rupp"
		date = "2021-01-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "1928358e-a64b-493f-a741-ae8e3d029374" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
