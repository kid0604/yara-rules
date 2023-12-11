rule win_seasalt_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.seasalt."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.seasalt"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 7410 8088????????20 8a9405ecfcffff ebe3 80a000d9001000 40 }
		$sequence_1 = { 53 f2ae a1???????? 68???????? f7d1 }
		$sequence_2 = { 57 8965f0 e8???????? b909000000 be???????? 8dbd78feffff 33c0 }
		$sequence_3 = { f3ab 8d8424f8030000 6860010000 50 8d8c247c010000 6880000000 }
		$sequence_4 = { 53 8d54241c 6804100000 52 }
		$sequence_5 = { c784247003000001000000 be???????? 8d44245c 8a10 8aca 3a16 }
		$sequence_6 = { 6a00 6804020000 50 56 ff15???????? 33c0 }
		$sequence_7 = { 8d41ff 83f80c 77b8 ff2485b01c0010 }
		$sequence_8 = { c3 55 ff15???????? 6a00 6a09 }
		$sequence_9 = { ff15???????? 8bd0 85d2 89542404 0f8419010000 53 }

	condition:
		7 of them and filesize <139264
}
