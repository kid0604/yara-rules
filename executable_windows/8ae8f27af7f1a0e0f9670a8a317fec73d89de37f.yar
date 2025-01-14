rule win_tiny_turla_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.tiny_turla."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tiny_turla"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 7521 488d4c2450 44896d7f e8???????? }
		$sequence_1 = { 48c744242000000000 488bd7 ff15???????? 85c0 7540 8b4c2450 }
		$sequence_2 = { e8???????? 488bf8 4885c0 0f8403010000 41b80e000000 }
		$sequence_3 = { 4c8be8 4885c0 0f84d8010000 488b5628 }
		$sequence_4 = { 4889742458 48897c2430 e8???????? 498907 }
		$sequence_5 = { 488bcf e8???????? 413bc6 7407 }
		$sequence_6 = { 66894308 488d5b10 413bfe 72d3 488d5e18 488bcb }
		$sequence_7 = { 740e ff15???????? 48c74310ffffffff 33c0 e9???????? 4533c9 4c8d442450 }
		$sequence_8 = { 488bcf e8???????? 8bc8 8bd8 e8???????? 4c8bf0 }
		$sequence_9 = { 488d5e10 488bcb e8???????? 4c8933 32db e9???????? 488bcf }

	condition:
		7 of them and filesize <51200
}
