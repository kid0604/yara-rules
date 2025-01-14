rule elf_nosedive_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects elf.nosedive."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.nosedive"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "linux"
		filetype = "executable"

	strings:
		$sequence_0 = { a801 0f84d1000000 48c7c098ffffff 64448b30 64c70000000000 41ffc7 7441 }
		$sequence_1 = { eb02 31c9 488b4038 4c89542428 48890c24 4889c7 4889442418 }
		$sequence_2 = { 895d10 48894508 85db 0f8e81000000 4531ff 0f1f00 4489fe }
		$sequence_3 = { 85c0 0f8fb2030000 4c8da3be000000 4c89e7 e8???????? 85c0 0f8f7b030000 }
		$sequence_4 = { 894f78 898740010000 f3410f6f01 0f118744010000 f3410f6f4910 0f118f54010000 f3410f6f5120 }
		$sequence_5 = { 4531c0 4c8b4c2418 488b742410 49bfffffffffffff0000 4c89cb 4d89cd 4d21cf }
		$sequence_6 = { e8???????? 4d89e1 4189d8 4c89e2 4889c1 4889ee 4c89f7 }
		$sequence_7 = { 880f c3 8b4c16fc 8b36 894c17fc 8937 c3 }
		$sequence_8 = { a801 7527 488b8790000000 48837f6800 48890424 7415 488b0424 }
		$sequence_9 = { b902160000 e9???????? 4c8d052df80e00 b9f7150000 be01000000 488d156cf30e00 e8???????? }

	condition:
		7 of them and filesize <3268608
}
