rule win_dustpan_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.dustpan."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dustpan"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 4533c0 4c891d???????? e8???????? 488d0d32010000 4883c420 5b e9???????? }
		$sequence_1 = { b9ff000000 e8???????? 488bfb 4803ff 4c8d2d45eb0000 }
		$sequence_2 = { 488d0d19a80100 33d2 c744242800000008 895c2420 ffd0 488b4d00 4833cc }
		$sequence_3 = { 4c8be7 4c8bf7 49c1fe05 4c8d3dffb60000 }
		$sequence_4 = { 488d05fb0a0100 eb04 4883c014 8918 e8???????? 4c8d15e30a0100 4885c0 }
		$sequence_5 = { 7440 66448923 8a45d8 4b8b8cf8e0d00100 88443109 8a45d9 }
		$sequence_6 = { e9???????? 488d0d45010000 e9???????? 4883ec28 488d0d12910000 e8???????? 488d0d39010000 }
		$sequence_7 = { 488bca 48c1f905 4c8d0533760100 83e21f }
		$sequence_8 = { 4889442420 e8???????? 488d8380000000 803800 741d 4c8d0df2bc0000 41b802000000 }
		$sequence_9 = { 894704 e9???????? 488d0d351f0100 48394c2458 7427 }

	condition:
		7 of them and filesize <282624
}
