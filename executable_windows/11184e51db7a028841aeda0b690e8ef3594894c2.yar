rule win_mistcloak_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.mistcloak."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mistcloak"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b049590500110 f644082801 740b 56 e8???????? 59 8bf0 }
		$sequence_1 = { 660f282d???????? 660f59f5 660f28aa70100110 660f54e5 660f58fe 660f58fc }
		$sequence_2 = { 8b0c8590500110 8b45f8 807c012800 7d46 }
		$sequence_3 = { 0f85b1000000 8b4508 dd00 ebc2 c745e418120110 eb19 }
		$sequence_4 = { 6bc618 57 8db8104e0110 57 }
		$sequence_5 = { 7429 83e805 7415 83e801 0f8595010000 c745e408120110 }
		$sequence_6 = { c745e408120110 e9???????? c745e404120110 e9???????? 894de0 c745e404120110 e9???????? }
		$sequence_7 = { 85f6 7420 6bc618 57 8db8104e0110 57 }
		$sequence_8 = { 8bc1 3914c5781a0110 7408 40 }
		$sequence_9 = { 8b45b4 8b0c8590500110 8a043b 03ce 8b75dc 03cb 43 }

	condition:
		7 of them and filesize <196608
}