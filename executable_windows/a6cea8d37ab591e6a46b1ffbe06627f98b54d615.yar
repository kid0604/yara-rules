rule Molerats_Jul17_Sample_Dropper
{
	meta:
		description = "Detects Molerats sample dropper SFX - July 2017"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
		date = "2017-07-07"
		hash1 = "ad0b3ac8c573d84c0862bf1c912dba951ec280d31fe5b84745ccd12164b0bcdb"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Please remove %s from %s folder. It is unsecure to run %s until it is done." fullword wide
		$s2 = "sfxrar.exe" fullword ascii
		$s3 = "attachment.hta" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and all of them )
}
