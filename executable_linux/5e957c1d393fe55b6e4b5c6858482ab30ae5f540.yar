rule DropBear_SSH_Server
{
	meta:
		description = "Detects DropBear SSH Server (not a threat but used to maintain access)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
		date = "2016-01-03"
		score = 50
		hash = "0969daac4adc84ab7b50d4f9ffb16c4e1a07c6dbfc968bd6649497c794a161cd"
		os = "linux"
		filetype = "executable"

	strings:
		$s1 = "Dropbear server v%s https://matt.ucc.asn.au/dropbear/dropbear.html" fullword ascii
		$s2 = "Badly formatted command= authorized_keys option" fullword ascii
		$s3 = "This Dropbear program does not support '%s' %s algorithm" fullword ascii
		$s4 = "/etc/dropbear/dropbear_dss_host_key" fullword ascii
		$s5 = "/etc/dropbear/dropbear_rsa_host_key" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 2 of them
}
