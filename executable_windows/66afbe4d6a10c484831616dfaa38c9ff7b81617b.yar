import "pe"

rule MALWARE_Win_PurpleWave
{
	meta:
		author = "ditekSHen"
		description = "PurpleWave infostealer payload"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "/loader/" fullword ascii
		$s2 = "\\load_" fullword wide
		$s3 = "boundaryaswell" fullword ascii
		$s4 = "[passwords]" ascii
		$s5 = "[is_encrypted]" ascii
		$s6 = "[cookies]" ascii
		$s7 = ".?AVMozillaBrowser@@" fullword ascii
		$s8 = ".?AVChromeBrowser@@" fullword ascii
		$s9 = ".?AV?$money" ascii
		$s10 = "at t.me/LuckyStoreSupport" ascii

	condition:
		uint16(0)==0x5a4d and 7 of them
}
