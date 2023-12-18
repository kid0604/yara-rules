rule win_icondown_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.icondown."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.icondown"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 89442420 8b471c d1ee 52 50 83e601 }
		$sequence_1 = { 5f 5e 5d b801000000 5b c20400 8b461c }
		$sequence_2 = { 3bc5 7c10 5f 5e 5d b8feffffff 5b }
		$sequence_3 = { 8b461c 85c0 0f8476010000 8b868c000000 }
		$sequence_4 = { 0fb6da f683c11c450004 7406 8816 46 40 ff01 }
		$sequence_5 = { b81f85eb51 f7e9 c1fa05 8bca b81f85eb51 c1e91f }
		$sequence_6 = { 56 8bf1 33db 57 8975f0 895dec c745e8a4ff4300 }
		$sequence_7 = { e8???????? c7462844d04300 833d????????00 7416 }
		$sequence_8 = { c3 33c0 5e c3 8b442404 c74050f0b94400 }
		$sequence_9 = { c745f020d04300 c745e810000000 e8???????? 85c0 7403 }

	condition:
		7 of them and filesize <5505024
}
