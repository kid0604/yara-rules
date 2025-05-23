rule win_cerber_auto_alt_5
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.cerber."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cerber"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff36 ff15???????? 899e14010000 eb06 }
		$sequence_1 = { 85c9 7435 8b550c 8d3c8a 8b4d08 2bca 894df4 }
		$sequence_2 = { 8b7d10 eb04 83248b00 85c9 }
		$sequence_3 = { 85c0 7427 52 e8???????? 59 85c0 }
		$sequence_4 = { 7c28 8bc1 3bc1 7522 8b8cc3f03b0000 }
		$sequence_5 = { 3b8374010000 7e06 898374010000 ff7510 50 53 e8???????? }
		$sequence_6 = { d3ee 85c9 7414 ff7514 51 ff7508 }
		$sequence_7 = { 8b5d08 8bc3 c1e002 50 ff750c e8???????? }

	condition:
		7 of them and filesize <573440
}
