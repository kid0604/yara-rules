rule win_magic_rat_auto_alt_2
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.magic_rat."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.magic_rat"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { eb1c 85c0 7910 ba00200000 29c2 89d0 c1f80e }
		$sequence_1 = { 0f842f010000 83f8ff 740e f0832d????????01 }
		$sequence_2 = { c1e010 eb1c 85c0 7910 ba00200000 29c2 89d0 }
		$sequence_3 = { 7442 81fa???????? 742a 81fa???????? 7442 81fa???????? 744a }
		$sequence_4 = { f6c380 b801000000 750d 89d8 c1e806 83f001 83e001 }
		$sequence_5 = { 66251ffc 0c80 66894348 e9???????? }
		$sequence_6 = { 85c0 7910 ba00200000 29c2 89d0 c1f80e }
		$sequence_7 = { c0e902 83e101 09ca c1e202 }
		$sequence_8 = { 0fb754244c 69d2e8030000 01d0 0fb754244e }
		$sequence_9 = { 660f28c8 f20f5c0d???????? f20f2cd1 660fefc9 f20f2aca f20f5cc1 }

	condition:
		7 of them and filesize <41843712
}
