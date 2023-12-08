rule Impacket_Tools_sniff_alt_1
{
	meta:
		description = "Compiled Impacket Tools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		date = "2017-04-07"
		hash1 = "8ab2b60aadf97e921e3a9df5cf1c135fbc851cb66d09b1043eaaa1dc01b9a699"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "ssniff" fullword ascii
		$s2 = "impacket.eap(" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <15000KB and all of them )
}
