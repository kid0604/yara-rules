rule Molerats_Jul17_Sample_3
{
	meta:
		description = "Detects Molerats sample - July 2017"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
		date = "2017-07-07"
		hash1 = "995eee4122802c2dc83bb619f8c53173a5a9c656ad8f43178223d78802445131"
		hash2 = "fec657a19356753008b0f477083993aa5c36ebaf7276742cf84bfe614678746b"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "ccleaner.exe" fullword wide
		$s2 = "Folder.exe" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and all of them )
}
