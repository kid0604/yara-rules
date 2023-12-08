import "pe"

rule HKTL_NET_GUID_TheHackToolBoxTeek_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/teeknofil/TheHackToolBoxTeek"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "2aa8c254-b3b3-469c-b0c9-dcbe1dd101c0" ascii wide
		$typelibguid0up = "2AA8C254-B3B3-469C-B0C9-DCBE1DD101C0" ascii wide
		$typelibguid1lo = "afeff505-14c1-4ecf-b714-abac4fbd48e7" ascii wide
		$typelibguid1up = "AFEFF505-14C1-4ECF-B714-ABAC4FBD48E7" ascii wide
		$typelibguid2lo = "4cf42167-a5cf-4b2d-85b4-8e764c08d6b3" ascii wide
		$typelibguid2up = "4CF42167-A5CF-4B2D-85B4-8E764C08D6B3" ascii wide
		$typelibguid3lo = "118a90b7-598a-4cfc-859e-8013c8b9339c" ascii wide
		$typelibguid3up = "118A90B7-598A-4CFC-859E-8013C8B9339C" ascii wide
		$typelibguid4lo = "3075dd9a-4283-4d38-a25e-9f9845e5adcb" ascii wide
		$typelibguid4up = "3075DD9A-4283-4D38-A25E-9F9845E5ADCB" ascii wide
		$typelibguid5lo = "295655e8-2348-4700-9ebc-aa57df54887e" ascii wide
		$typelibguid5up = "295655E8-2348-4700-9EBC-AA57DF54887E" ascii wide
		$typelibguid6lo = "74efe601-9a93-46c3-932e-b80ab6570e42" ascii wide
		$typelibguid6up = "74EFE601-9A93-46C3-932E-B80AB6570E42" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
