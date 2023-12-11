rule Impacket_Tools_smbrelayx
{
	meta:
		description = "Compiled Impacket Tools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		date = "2017-04-07"
		hash1 = "9706eb99e48e445ac4240b5acb2efd49468a800913e70e40b25c2bf80d6be35f"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "impacket.examples.secretsdump" fullword ascii
		$s2 = "impacket.examples.serviceinstall" fullword ascii
		$s3 = "impacket.smbserver(" ascii
		$s4 = "SimpleHTTPServer(" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <18000KB and 3 of them )
}
