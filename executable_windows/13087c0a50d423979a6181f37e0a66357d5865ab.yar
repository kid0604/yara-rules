rule win_h1n1_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.h1n1."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.h1n1"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 49 85c9 0f8527ffffff ff75f8 }
		$sequence_1 = { 49 75b6 8bcf 2b4d0c 83e103 }
		$sequence_2 = { 83bdecfeffff01 7505 bb07000000 93 5b c9 c3 }
		$sequence_3 = { aa ac 0ac0 740e 3c3d 740a e8???????? }
		$sequence_4 = { 0345f4 8b8ba4000000 85c9 742b }
		$sequence_5 = { ff7508 6a00 ff35???????? 58 ffd0 }
		$sequence_6 = { 351f5b5742 ab 05f8383ad2 ab ff75fc }
		$sequence_7 = { 59 85c0 75d1 83bb8000000000 7465 }
		$sequence_8 = { 8d8614850010 50 ffb610850010 57 }
		$sequence_9 = { 59 c3 56 8b742408 6804010000 68f8820010 }
		$sequence_10 = { 330c85908f0010 42 3b54240c 72e4 f7d1 8bc1 }
		$sequence_11 = { 57 8d3c95c0850010 8b0f 334f04 23cb }
		$sequence_12 = { 330d???????? 5b 8bc1 83e001 d1e9 330c8500850010 330d???????? }
		$sequence_13 = { 57 50 e8???????? 68f4600010 56 }
		$sequence_14 = { 33d2 a3???????? 42 b9c0850010 8b01 c1e81e 3301 }
		$sequence_15 = { 6800800010 ff742410 e8???????? 6823af2930 56 ff742410 }

	condition:
		7 of them and filesize <172032
}
