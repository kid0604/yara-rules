rule XOR_4byte_Key
{
	meta:
		description = "Detects an executable encrypted with a 4 byte XOR (also used for Derusbi Trojan)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
		date = "2015-12-15"
		score = 60
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = { 85 C9 74 0A 31 06 01 1E 83 C6 04 49 EB F2 }

	condition:
		uint16(0)==0x5a4d and filesize <900KB and all of them
}
