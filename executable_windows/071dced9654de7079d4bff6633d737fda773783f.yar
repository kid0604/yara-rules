rule Impacket_Tools_ifmap
{
	meta:
		description = "Compiled Impacket Tools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		date = "2017-04-07"
		hash1 = "20a1f11788e6cc98a76dca2db4691963c054fc12a4d608ac41739b98f84b3613"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "bifmap.exe.manifest" fullword ascii
		$s2 = "impacket.dcerpc.v5.epm(" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <15000KB and all of them )
}
