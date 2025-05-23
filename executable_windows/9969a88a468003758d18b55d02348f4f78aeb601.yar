rule win_lpeclient_auto_alt_2
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.lpeclient."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lpeclient"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 33d2 897590 e8???????? 488d8dc2000000 33d2 }
		$sequence_1 = { 33d2 41b808040000 e8???????? 488bcf ff15???????? 488bce ff15???????? }
		$sequence_2 = { 488d0df74e0100 ff15???????? 488d0d9a480100 ff15???????? }
		$sequence_3 = { ff15???????? 488d4de0 33d2 41b808040000 488bd8 e8???????? 488d4de0 }
		$sequence_4 = { ff15???????? 488d9500040000 488bc8 ff15???????? 488d4de0 33d2 }
		$sequence_5 = { 4885c0 753b 488d4dd0 488d45d0 488b15???????? 482bd0 666666660f1f840000000000 }
		$sequence_6 = { c7451072007500 c7451473005000 c7451872006f00 c7451c64007500 c7452063007400 66894524 }
		$sequence_7 = { c7451c64007500 c7452063007400 66894524 c745b872006f00 c745bc6f007400 c745c05c005300 c745c465006300 }
		$sequence_8 = { 85c0 74dc 4c8d85a0070000 488d1504f70000 }
		$sequence_9 = { 85c0 0f8e87140000 48895c2470 48896c2450 4d8d6208 4c89742438 4c8d5702 }

	condition:
		7 of them and filesize <289792
}
