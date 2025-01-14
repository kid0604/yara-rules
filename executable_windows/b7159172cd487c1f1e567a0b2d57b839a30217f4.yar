rule win_chthonic_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.chthonic."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.chthonic"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b10 8911 0fb64dff 46 }
		$sequence_1 = { 6a04 56 8d4604 68fc0f0000 }
		$sequence_2 = { 81e1ff00ff00 0bc1 89470c 5f }
		$sequence_3 = { 32cb 80e17f 8808 b001 5b c3 }
		$sequence_4 = { 8911 8b00 8b4d08 03c2 25ff000080 7907 48 }
		$sequence_5 = { ff751c ff7518 ff7514 53 ff7510 ff7508 e8???????? }
		$sequence_6 = { b8ecff0000 660145f0 8d45f0 50 56 e8???????? }
		$sequence_7 = { 4e 81ce00ffffff 46 8d84b5fcfbffff 8b08 03f9 81e7ff000080 }
		$sequence_8 = { 83e601 eb00 85f6 74cf 8345fc02 b9000d0000 }
		$sequence_9 = { c1c108 81e1ff00ff00 0bc1 89470c }

	condition:
		7 of them and filesize <425984
}
