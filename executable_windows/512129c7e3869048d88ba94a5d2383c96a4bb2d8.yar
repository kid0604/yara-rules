rule StuxNet_dll
{
	meta:
		description = "Stuxnet Sample - file dll.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-07-09"
		hash1 = "9e392277f62206098cf794ddebafd2817483cfd57ec03c2e05e7c3c81e72f562"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "SUCKM3 FROM EXPLORER.EXE MOTH4FUCKA #@!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and $s1
}
