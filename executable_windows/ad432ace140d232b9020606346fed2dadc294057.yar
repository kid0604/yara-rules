import "pe"

rule HKTL_NET_GUID_ExploitRemotingService_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/tyranid/ExploitRemotingService"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "fd17ae38-2fd3-405f-b85b-e9d14e8e8261" ascii wide
		$typelibguid0up = "FD17AE38-2FD3-405F-B85B-E9D14E8E8261" ascii wide
		$typelibguid1lo = "1850b9bb-4a23-4d74-96b8-58f274674566" ascii wide
		$typelibguid1up = "1850B9BB-4A23-4D74-96B8-58F274674566" ascii wide
		$typelibguid2lo = "297cbca1-efa3-4f2a-8d5f-e1faf02ba587" ascii wide
		$typelibguid2up = "297CBCA1-EFA3-4F2A-8D5F-E1FAF02BA587" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
