rule win_shady_hammock_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.shady_hammock."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shady_hammock"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 480f4de8 4c8bc5 e8???????? 498b07 482bdd }
		$sequence_1 = { ffc3 3b5f18 72d9 33c0 488b5c2450 }
		$sequence_2 = { 3b5f18 72d9 33c0 488b5c2450 488b6c2458 488b742460 4883c420 }
		$sequence_3 = { 48d1e9 482bc1 4c3bf8 77e3 }
		$sequence_4 = { 4c0f45452f 498b02 488d4d27 48894c2438 488d4d18 }
		$sequence_5 = { 488d4101 488903 8b4314 488b0b c1e80c a801 }
		$sequence_6 = { 4803d1 eb03 0fb7d1 498bce ff15???????? }
		$sequence_7 = { 488bc6 488bd9 482bc2 493bc0 4c0f42c8 4883791810 488bc1 }
		$sequence_8 = { 7413 4c8bc3 ba01000000 498bcf e8???????? }
		$sequence_9 = { 66ffc6 663b7706 72cf 488bd7 }

	condition:
		7 of them and filesize <635904
}
