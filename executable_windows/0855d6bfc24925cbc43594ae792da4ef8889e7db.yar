import "pe"

rule HKTL_NET_GUID_Farmer
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/mdsecactivebreach/Farmer"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-22"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "37da2573-d9b5-4fc2-ae11-ccb6130cea9f" ascii wide
		$typelibguid0up = "37DA2573-D9B5-4FC2-AE11-CCB6130CEA9F" ascii wide
		$typelibguid1lo = "49acf861-1c10-49a1-bf26-139a3b3a9227" ascii wide
		$typelibguid1up = "49ACF861-1C10-49A1-BF26-139A3B3A9227" ascii wide
		$typelibguid2lo = "9a6c028f-423f-4c2c-8db3-b3499139b822" ascii wide
		$typelibguid2up = "9A6C028F-423F-4C2C-8DB3-B3499139B822" ascii wide
		$typelibguid3lo = "1c896837-e729-46a9-92b9-3bbe7ac2c90d" ascii wide
		$typelibguid3up = "1C896837-E729-46A9-92B9-3BBE7AC2C90D" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
