rule win_oatboat_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.oatboat."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.oatboat"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c745e04e744672 c745e465655669 c745e872747561 c745ec6c4d656d c745f06f727900 e8???????? }
		$sequence_1 = { 488bf9 c745e04b004500 33db c745e452004e00 488d4de0 66895df8 c745e845004c00 }
		$sequence_2 = { c745e46f70794d c745e8656d6f72 66c745ec7900 e8???????? 4d8bc4 }
		$sequence_3 = { e8???????? 488bcf ffd0 488b5c2450 488b742458 488b7c2460 4883c430 }
		$sequence_4 = { c740e86c000000 e8???????? 4885c0 740e 488bd7 488bc8 e8???????? }
		$sequence_5 = { 4883653000 488d4de0 4c896538 c745e04e74416c c745e46c6f6361 c745e874655669 c745ec72747561 }
		$sequence_6 = { c745f46f727900 e8???????? 4c8d4d38 c744242840000000 4533c0 }
		$sequence_7 = { 0f84a3000000 4d8b5210 4d85d2 0f8496000000 4d397a30 0f848c000000 498b5a60 }

	condition:
		7 of them and filesize <58368
}
