rule win_anatova_ransom_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.anatova_ransom."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.anatova_ransom"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? 8b4d8c 4863c9 4839c1 0f832a000000 e9???????? 8b458c }
		$sequence_1 = { 0f8521000000 488b4598 4989c2 4c89d1 }
		$sequence_2 = { 48898510ffffff 488d051f580000 48898518ffffff 488d051b580000 }
		$sequence_3 = { e9???????? 48b80000100000000000 e9???????? 488b45e8 4889442428 }
		$sequence_4 = { 0f8dd3fcffff 83f808 0f845bfcffff 83f809 0f8477fcffff 83f80a 0f8493fcffff }
		$sequence_5 = { 488b4d10 488b5528 488945c8 488b4520 48894dc0 }
		$sequence_6 = { 0fb68597fdffff 83f800 0f8405000000 e9???????? 488b8598fdffff 4989c2 }
		$sequence_7 = { 488945f0 488b45f0 4883f8ff 0f84aa080000 48b80000000000000000 4989c3 488b45f0 }
		$sequence_8 = { 4889e5 4881ec70000000 b800000000 8845ff 488b05???????? 4883f800 }
		$sequence_9 = { 488d05d6390000 488985f8feffff 488d05d5390000 48898500ffffff 488d05d3390000 48898508ffffff }

	condition:
		7 of them and filesize <671744
}
