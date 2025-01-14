rule win_qaccel_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.qaccel."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.qaccel"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 3bd0 0f87ea010000 e9???????? 8b4df4 33ff 81e1ffff0000 }
		$sequence_1 = { 6a0c 8bd8 ffd7 8bf8 8b4620 8d55f0 52 }
		$sequence_2 = { 41 83c210 894df8 8b1b }
		$sequence_3 = { 85c0 0f84b8000000 0f8810000000 0f890a000000 5f }
		$sequence_4 = { 0f8488000000 53 57 56 8d4d9c e8???????? 8b7da0 }
		$sequence_5 = { 33c0 8d95fcfeffff f2ae f7d1 2bf9 }
		$sequence_6 = { 8b45fc 51 8b4df4 2bc1 2bc7 40 99 }
		$sequence_7 = { 8b1d???????? f7d1 49 742d 8945fc 8d45fc }
		$sequence_8 = { 03da 668b03 50 ffd6 668b4b02 8bf8 51 }
		$sequence_9 = { f3a4 668b4df8 668903 66894b02 ff15???????? }

	condition:
		7 of them and filesize <106496
}
