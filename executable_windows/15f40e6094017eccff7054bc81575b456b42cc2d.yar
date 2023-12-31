rule win_nimplant_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.nimplant."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nimplant"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 4c89e9 0f11642440 e8???????? 803b00 0f8515ffffff 488b4c2468 4885c9 }
		$sequence_1 = { 894c2430 4889ac24b0000000 e9???????? 4981ffff7f0000 4c89f2 488b4b08 490f4ed7 }
		$sequence_2 = { 488d051e3a0800 48895110 48894120 48c741183a000000 48c7410800000000 48c7442420a1060000 e8???????? }
		$sequence_3 = { e8???????? 488b442440 488b542448 44886c0208 4883c001 0f8093040000 488b542448 }
		$sequence_4 = { e8???????? 4c8b442430 48ba0000000000000040 4889f1 4c01e9 0f80b1000000 4885c9 }
		$sequence_5 = { f30f6f25???????? 4889ea 41b8a94d975e 4c89e9 4c899c2408010000 4c89942400010000 0f11a42410010000 }
		$sequence_6 = { 488b9424f0000000 4889d1 4883e904 0f80de0f0000 4839ca 0f8e58100000 4885c9 }
		$sequence_7 = { e8???????? 803b00 488b942488000000 488b842480000000 0f8599feffff 4c8b4e58 4c89f1 }
		$sequence_8 = { 80f90b 0f873b1a0000 0fb6f2 83ee01 4863f6 4883c60c 48c1e604 }
		$sequence_9 = { 4889eb 48897c2440 488b7c2438 4889c5 4c89ee 4c897c2460 }

	condition:
		7 of them and filesize <1811456
}
