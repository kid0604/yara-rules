rule HttpBrowser_RAT_Sample1
{
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Sample update.hancominc.com"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 80
		hash1 = "be334d1f8fa65a723af65200a166c2bbdb06690c8b30fafe772600e4662fc68b"
		hash2 = "1052ad7f4d49542e4da07fa8ea59c15c40bc09a4d726fad023daafdf05866ebb"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "update.hancominc.com" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and $s0
}
