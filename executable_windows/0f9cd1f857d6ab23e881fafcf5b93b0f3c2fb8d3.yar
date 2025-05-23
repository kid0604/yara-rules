rule win_gtpdoor_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.gtpdoor."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gtpdoor"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { fc b932000000 b800000000 f3aa }
		$sequence_1 = { 0fb600 31d0 8801 8045fb01 8345fc01 }
		$sequence_2 = { e8???????? 8945c8 837dc8ff 7528 e8???????? 8b38 e8???????? }
		$sequence_3 = { 8945f4 8d950afaffff b8dc050000 89442408 c744240400000000 891424 e8???????? }
		$sequence_4 = { fc 488bbda0f1ffff f2ae 4889c8 48f7d0 }
		$sequence_5 = { 55 48833d????????00 4889e5 7416 b800000000 4885c0 740c }
		$sequence_6 = { a3???????? a1???????? c744240800000000 c744240400000000 890424 }
		$sequence_7 = { 0fb64009 3c01 757b 8b45e8 83c00c }
		$sequence_8 = { f7d0 8d50ff 8b45e8 83c00c bf???????? }
		$sequence_9 = { c9 c3 55 4889e5 48897de8 488955d8 4c8945c8 }
		$sequence_10 = { 8b7dd4 f2ae 89c8 f7d0 83e801 83c001 }
		$sequence_11 = { 8b450c 8945ea c645ee00 0fb68504faffff }
		$sequence_12 = { 4c89c9 e8???????? 8945fc 8b75fc bf???????? b800000000 }
		$sequence_13 = { 4889c2 480355e0 0fb645ff 8802 }

	condition:
		7 of them and filesize <4210688
}
