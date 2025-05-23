rule win_lowzero_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.lowzero."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lowzero"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 53 ffd0 85c0 750a 685a040000 e9???????? c7471001000000 }
		$sequence_1 = { 7439 03c3 837f1400 7425 }
		$sequence_2 = { 8b45d4 89473c 8b441154 3945f4 7318 6a0d ff15???????? }
		$sequence_3 = { 47 2bc8 8d4602 03c3 3b450c }
		$sequence_4 = { e8???????? 83c40c 03f3 eb0b 2bce 8a0431 }
		$sequence_5 = { 8945f0 8945d8 eb25 8b03 }
		$sequence_6 = { 0fb61f 83c307 47 0fb607 47 2bc8 }
		$sequence_7 = { 56 e8???????? 8b55fc 8bca 57 8b423c 8b55f4 }
		$sequence_8 = { 2bca 49 83fb07 7507 0fb61f 83c307 }
		$sequence_9 = { 6a01 53 ffd0 85c0 750a 685a040000 }

	condition:
		7 of them and filesize <433152
}
