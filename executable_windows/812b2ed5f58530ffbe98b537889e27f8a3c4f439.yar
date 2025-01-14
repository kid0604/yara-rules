rule win_cabart_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.cabart."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cabart"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 6804010000 50 ff15???????? 83c410 6a10 68???????? 8d85fcfeffff }
		$sequence_1 = { 85d2 7ff4 eb01 42 2bca }
		$sequence_2 = { 83c420 ff7508 ffd6 8bf8 }
		$sequence_3 = { 8975fc 5f 395d10 740e 57 }
		$sequence_4 = { 7d0a 686c090000 e8???????? 8b0f }
		$sequence_5 = { 7ff4 eb01 42 2bca }
		$sequence_6 = { 6a50 5e 53 53 53 }
		$sequence_7 = { 8bd8 ff15???????? 3bdf 5b }
		$sequence_8 = { ff750c ff7508 56 ff15???????? 56 8bd8 }
		$sequence_9 = { 68bb0b0000 ebe2 85ff 7507 68bc0b0000 ebd7 }

	condition:
		7 of them and filesize <32768
}
