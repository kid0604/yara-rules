import "pe"

rule HKTL_NET_GUID_DInvisibleRegistry_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NVISO-BE/DInvisibleRegistry"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "31d576fb-9fb9-455e-ab02-c78981634c65" ascii wide
		$typelibguid0up = "31D576FB-9FB9-455E-AB02-C78981634C65" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
