rule Impacket_Tools_smbexec
{
	meta:
		description = "Compiled Impacket Tools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		date = "2017-04-07"
		hash1 = "7d715217e23a471d42d95c624179fe7de085af5670171d212b7b798ed9bf07c2"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "logging.config(" ascii
		$s2 = "ssmbexec" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <17000KB and all of them )
}
