rule Duqu2_Sample3
{
	meta:
		description = "Detects Duqu2 Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		date = "2016-07-02"
		score = 80
		hash1 = "2a9a5afc342cde12c6eb9a91ad29f7afdfd8f0fb17b983dcfddceccfbc17af69"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "SELECT `%s` FROM `%s` WHERE `%s`='CAData%i'" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <50KB and $s1)
}
