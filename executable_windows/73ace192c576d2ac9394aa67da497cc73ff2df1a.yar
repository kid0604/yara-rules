rule win_protonbot_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.protonbot."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.protonbot"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? 68???????? 8d85f0feffff 50 8d85d4feffff 50 e8???????? }
		$sequence_1 = { e8???????? 83c418 6804010000 8d85ecfeffff c745fc00000000 }
		$sequence_2 = { c68574feffff00 8a01 41 84c0 75f9 2bca 8d85ecfeffff }
		$sequence_3 = { 0f4385d8feffff 50 8d85f0feffff 68ff000000 50 e8???????? 68???????? }
		$sequence_4 = { 8bda 8bf9 8d8dd8feffff e8???????? 8d85f0feffff c745fc00000000 }
		$sequence_5 = { 8bcc 50 e8???????? e8???????? 8bcc }
		$sequence_6 = { 8d8dd8feffff e8???????? 8d85f0feffff c745fc00000000 50 68ff000000 }
		$sequence_7 = { c645e400 8bcf ff75e4 53 }
		$sequence_8 = { 68???????? c60100 e8???????? 83ec18 c645fc06 }
		$sequence_9 = { 8b1d???????? be02000000 66a3???????? 6a00 }

	condition:
		7 of them and filesize <1073152
}