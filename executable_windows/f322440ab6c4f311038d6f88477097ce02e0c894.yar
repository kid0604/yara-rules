rule win_wonknu_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.wonknu."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wonknu"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? 8bfc b901050000 f3a5 8bcb e8???????? 803b00 }
		$sequence_1 = { eb08 c6840550ffffff00 8d8550ffffff 50 e8???????? }
		$sequence_2 = { 8bfc b901050000 f3a5 8bcb e8???????? 803b00 }
		$sequence_3 = { 8d7e28 57 ff15???????? 8b4608 }
		$sequence_4 = { e8???????? 8bfc b901050000 f3a5 8bcb }
		$sequence_5 = { f3a5 8bcb e8???????? 803b00 }
		$sequence_6 = { 8bfc b901050000 f3a5 8bcb }
		$sequence_7 = { c6840550ffffff00 8d8550ffffff 50 e8???????? }
		$sequence_8 = { 53 56 57 6804140000 }
		$sequence_9 = { e8???????? 8bfc b901050000 f3a5 8bcb e8???????? }

	condition:
		7 of them and filesize <540672
}
