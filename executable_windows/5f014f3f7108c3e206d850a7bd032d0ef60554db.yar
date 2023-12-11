import "pe"

rule HKTL_NET_GUID_DLL_Injector_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/tmthrgd/DLL-Injector"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "4581a449-7d20-4c59-8da2-7fd830f1fd5e" ascii wide
		$typelibguid0up = "4581A449-7D20-4C59-8DA2-7FD830F1FD5E" ascii wide
		$typelibguid1lo = "05f4b238-25ce-40dc-a890-d5bbb8642ee4" ascii wide
		$typelibguid1up = "05F4B238-25CE-40DC-A890-D5BBB8642EE4" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
