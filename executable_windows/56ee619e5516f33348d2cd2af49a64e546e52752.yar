rule win_thanatos_ransom_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.thanatos_ransom."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.thanatos_ransom"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b0485e0774300 894df0 8a440129 8b4d08 8845ff }
		$sequence_1 = { e8???????? 3bf0 7419 4e }
		$sequence_2 = { e8???????? 83c404 c645fc0e 83781410 7202 8b00 }
		$sequence_3 = { c644012801 8b0495e0774300 897c0118 8bfe e9???????? }
		$sequence_4 = { e8???????? c645fc04 8b45d4 83f810 7242 8b4dc0 }
		$sequence_5 = { e9???????? 8d8db8feffff e9???????? 8d8d70feffff e9???????? 8d8d88feffff }
		$sequence_6 = { ff15???????? 8b859cfeffff 83f810 7245 8b8d88feffff }
		$sequence_7 = { 6a04 58 6bc000 8b4d08 898814714300 }
		$sequence_8 = { ff758c e8???????? 33c0 c745a007000000 c7459c00000000 6689458c 39856cffffff }
		$sequence_9 = { 6af6 ff15???????? 8b04bde0774300 834c0318ff 33c0 }

	condition:
		7 of them and filesize <516096
}
