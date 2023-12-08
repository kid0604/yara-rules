import "pe"

rule HKTL_NET_GUID_SharPersist_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/fireeye/SharPersist"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "9d1b853e-58f1-4ba5-aefc-5c221ca30e48" ascii wide
		$typelibguid0up = "9D1B853E-58F1-4BA5-AEFC-5C221CA30E48" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
