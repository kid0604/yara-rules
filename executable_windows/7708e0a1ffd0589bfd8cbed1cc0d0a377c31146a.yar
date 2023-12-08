import "pe"

rule HKTL_NET_GUID_SharpAdidnsdump_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/b4rtik/SharpAdidnsdump"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "cdb02bc2-5f62-4c8a-af69-acc3ab82e741" ascii wide
		$typelibguid0up = "CDB02BC2-5F62-4C8A-AF69-ACC3AB82E741" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
