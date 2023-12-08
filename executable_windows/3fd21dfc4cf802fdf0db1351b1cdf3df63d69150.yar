import "pe"

rule HKTL_NET_GUID_rat_shell_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/stphivos/rat-shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "7a15f8f6-6ce2-4ca4-919d-2056b70cc76a" ascii wide
		$typelibguid0up = "7A15F8F6-6CE2-4CA4-919D-2056B70CC76A" ascii wide
		$typelibguid1lo = "1659d65d-93a8-4bae-97d5-66d738fc6f6c" ascii wide
		$typelibguid1up = "1659D65D-93A8-4BAE-97D5-66D738FC6F6C" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
