rule win_joao_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.joao."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.joao"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 6a00 6a00 68b0000000 b9???????? e8???????? }
		$sequence_1 = { 833f10 720e 8b03 50 e8???????? 8b4510 }
		$sequence_2 = { 741c 8b0f 8908 8d4804 83c704 }
		$sequence_3 = { 40 50 8d4ef0 51 53 e8???????? }
		$sequence_4 = { e8???????? 83c404 897e14 897e18 897e1c 8b4604 }
		$sequence_5 = { c745d000000000 85c9 746f 8b4320 03c6 8945cc }
		$sequence_6 = { 837de810 8b45d4 7303 8d45d4 52 51 50 }
		$sequence_7 = { 52 8d4dd0 e8???????? 83f8ff 740b 6aff 50 }
		$sequence_8 = { 3bd1 7299 837de810 720c }
		$sequence_9 = { 52 8bce c745f802000000 897dfc e8???????? }

	condition:
		7 of them and filesize <2867200
}
