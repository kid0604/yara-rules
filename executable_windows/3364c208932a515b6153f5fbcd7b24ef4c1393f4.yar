rule CN_Honker_net_priv_esc2
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file net-priv-esc2.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "4851e0088ad38ac5b3b1c75302a73698437f7f17"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Usage:%s username password" fullword ascii
		$s2 = "<www.darkst.com>" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <17KB and all of them
}
