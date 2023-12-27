rule win_lemonduck_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.lemonduck."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lemonduck"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 41c1e018 42330c22 450bc8 46334c2204 4433d9 410fb64625 4533d1 }
		$sequence_1 = { 488b7c2430 33c0 488983a0000000 488983a8000000 488983b0000000 488983b8000000 488983c0000000 }
		$sequence_2 = { 418bc0 80f909 410f47c2 02c1 41884102 410fb64d01 80e10f }
		$sequence_3 = { 488b89d8000000 48896c2438 4889742440 4883f9ff 7414 ff15???????? 8b4758 }
		$sequence_4 = { 488d15d2280a00 488bcb ff15???????? 488905???????? 4885c0 0f8474010000 488d159a280a00 }
		$sequence_5 = { 488d05c6ba0000 488905???????? 488d0558c70000 488905???????? 488d05bad20000 488905???????? 488d054ce30000 }
		$sequence_6 = { 41c1e908 410fb6c7 41c1ef08 418bb48a50951600 400fb6cf 458ba48250951600 410fb6c6 }
		$sequence_7 = { 482bc1 4883c0f8 4883f81f 0f8798000000 ba4f000100 e8???????? 90 }

	condition:
		7 of them and filesize <10011648
}