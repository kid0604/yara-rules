import "pe"

rule HKTL_NET_GUID_VanillaRAT_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/DannyTheSloth/VanillaRAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "d0f2ee67-0a50-423d-bfe6-845da892a2db" ascii wide
		$typelibguid0up = "D0F2EE67-0A50-423D-BFE6-845DA892A2DB" ascii wide
		$typelibguid1lo = "a593fcd2-c8ab-45f6-9aeb-8ab5e20ab402" ascii wide
		$typelibguid1up = "A593FCD2-C8AB-45F6-9AEB-8AB5E20AB402" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
