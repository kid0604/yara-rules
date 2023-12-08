import "pe"

rule HKTL_NET_GUID_ManagedInjection_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/malcomvetter/ManagedInjection"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "e5182bff-9562-40ff-b864-5a6b30c3b13b" ascii wide
		$typelibguid0up = "E5182BFF-9562-40FF-B864-5A6B30C3B13B" ascii wide
		$typelibguid1lo = "fdedde0d-e095-41c9-93fb-c2219ada55b1" ascii wide
		$typelibguid1up = "FDEDDE0D-E095-41C9-93FB-C2219ADA55B1" ascii wide
		$typelibguid2lo = "0dd00561-affc-4066-8c48-ce950788c3c8" ascii wide
		$typelibguid2up = "0DD00561-AFFC-4066-8C48-CE950788C3C8" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
