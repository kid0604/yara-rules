rule win_coinminer_auto_alt_5
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.coinminer."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.coinminer"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8bec 83ec10 8955f8 894dfc 56 57 85c9 }
		$sequence_1 = { 742e 837d1800 0f85cf020000 6800080000 }
		$sequence_2 = { a3???????? c705????????19c98f00 c705????????73c98f00 c705????????f8c98f00 a3???????? c705????????bdbf8f00 }
		$sequence_3 = { 8b0cbda05f9a00 f6440e0401 743d 833c0eff 7437 }
		$sequence_4 = { 8935???????? 85c9 7504 85f6 745b 8b7d14 }
		$sequence_5 = { 33c0 0f57c0 6689842450070000 33f6 660f13442440 }
		$sequence_6 = { c744242400004000 6a00 50 c744243000000000 c744246c00100000 c744247000000000 c744247400f00400 }
		$sequence_7 = { b8???????? c705????????88c88f00 a3???????? c705????????19c98f00 c705????????73c98f00 }
		$sequence_8 = { 7523 e8???????? 8bf8 8bca 893d???????? }
		$sequence_9 = { 55 8bec a1???????? 81ec9c010000 }

	condition:
		7 of them and filesize <1523712
}
