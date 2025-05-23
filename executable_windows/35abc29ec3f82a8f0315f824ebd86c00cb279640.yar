rule win_mirage_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.mirage."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mirage"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c745f804010000 ff75fc ff15???????? ff75fc }
		$sequence_1 = { 59 3bc3 59 7412 83c005 50 8d85ecfeffff }
		$sequence_2 = { 83c428 8935???????? b001 5f 5e 5b }
		$sequence_3 = { 8d45f4 50 53 68???????? c745f804010000 ff75fc }
		$sequence_4 = { be14410000 8d85d4beffff 56 53 50 e8???????? }
		$sequence_5 = { 7407 68f4010000 eb06 ff35???????? ff15???????? }
		$sequence_6 = { e8???????? 83c41c 8935???????? 8ac3 }
		$sequence_7 = { ff75fc ff15???????? 8b8514010000 2b7df4 8985e0bfffff 8d450d }
		$sequence_8 = { 8d8520010000 56 50 e8???????? 8b4510 }
		$sequence_9 = { 6801000080 ff15???????? 85c0 7556 }
		$sequence_10 = { 889590fcffff 33db f3ab 66ab 8d8d90feffff 895dfc }
		$sequence_11 = { 755d 8b06 385d08 8b08 }
		$sequence_12 = { 83c414 8d8530fbffff 53 50 e8???????? 59 50 }
		$sequence_13 = { 50 ff15???????? 8d4d9c 885dfc e8???????? }
		$sequence_14 = { 894518 e8???????? 8bf8 59 85ff 7504 33c0 }
		$sequence_15 = { 7405 83f847 7517 8d860c010000 }

	condition:
		7 of them and filesize <1695744
}
