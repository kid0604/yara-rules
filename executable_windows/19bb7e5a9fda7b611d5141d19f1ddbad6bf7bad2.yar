rule win_sidewinder_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.sidewinder."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sidewinder"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? 50 e8???????? 8bd0 8d4de8 e8???????? 8d45c8 }
		$sequence_1 = { 8d4dc4 e8???????? 8d45ac 89458c 8d458c 50 }
		$sequence_2 = { 8d4dcc e8???????? 8d45dc 898570ffffff c78568ffffff08400000 8d8568ffffff 50 }
		$sequence_3 = { 8965ec c745f0182c4000 c745f400000000 c745f800000000 6a01 e8???????? 8d45dc }
		$sequence_4 = { ff75bc 8b45cc 8b00 ff75cc ff5060 dbe2 8945b4 }
		$sequence_5 = { ff5004 8b4508 8b403c 0b450c 8b4d08 89413c 8b4508 }
		$sequence_6 = { 0f8053010000 668945ec 668b45ec 663b45d8 0f8f22010000 668365e400 }
		$sequence_7 = { 0f84df000000 66830d????????ff 8d45dc 50 8b45e8 8b00 ff75e8 }
		$sequence_8 = { e8???????? 898530ffffff eb07 83a530ffffff00 6a00 8b8568ffffff 83e801 }
		$sequence_9 = { e8???????? 68???????? 8d4ddc e8???????? 8d4dd8 e8???????? c3 }

	condition:
		7 of them and filesize <679936
}
