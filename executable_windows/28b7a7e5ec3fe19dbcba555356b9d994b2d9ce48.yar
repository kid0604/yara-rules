rule win_targetcompany_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.targetcompany."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.targetcompany"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? 83c424 8d8574ffffff 50 8d85ecdcffff 50 ff15???????? }
		$sequence_1 = { 75f1 8db57cffffff e8???????? 8bf0 }
		$sequence_2 = { 8945e4 3d01010000 7d0d 8a4c181c 8888d8e84100 40 ebe9 }
		$sequence_3 = { c20800 56 8bf0 81fffeffff7f 7605 e8???????? 8b4618 }
		$sequence_4 = { a5 ff759c 895dd0 53 6a40 ff15???????? 8bf0 }
		$sequence_5 = { 6a01 68???????? 33db 53 e8???????? 85c0 7c56 }
		$sequence_6 = { 8d45f8 50 6a1f 53 897de4 8975f8 ff15???????? }
		$sequence_7 = { 33c5 8945fc 53 56 57 8d9dccf9ffff 8bf9 }
		$sequence_8 = { 56 57 8945f4 8945f8 3905???????? 7516 8b0d???????? }
		$sequence_9 = { 25ffff7f00 c1e108 33d2 0bc8 0bda 8bc1 8b4df8 }

	condition:
		7 of them and filesize <328704
}
