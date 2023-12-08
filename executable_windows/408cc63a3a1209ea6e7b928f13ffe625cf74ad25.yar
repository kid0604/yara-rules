import "pe"
import "math"

rule StoneDrill_alt_1
{
	meta:
		description = "Detects malware from StoneDrill threat report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
		date = "2017-03-07"
		super_rule = 1
		hash1 = "2bab3716a1f19879ca2e6d98c518debb107e0ed8e1534241f7769193807aac83"
		hash2 = "62aabce7a5741a9270cddac49cd1d715305c1d0505e620bbeaec6ff9b6fd0260"
		hash3 = "69530d78c86031ce32583c6800f5ffc629acacb18aac4c8bb5b0e915fc4cc4db"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "C-Dlt-C-Trsh-T.tmp" fullword wide
		$x2 = "C-Dlt-C-Org-T.vbs" fullword wide
		$s1 = "Hello dear" fullword ascii
		$s2 = "WRZRZRAR" fullword ascii
		$opa1 = { 66 89 45 d8 6a 64 ff }
		$opa2 = { 8d 73 01 90 0f bf 51 fe }

	condition:
		uint16(0)==0x5a4d and filesize <700KB and 1 of ($x*) or ( all of ($op*) and all of ($s*))
}
