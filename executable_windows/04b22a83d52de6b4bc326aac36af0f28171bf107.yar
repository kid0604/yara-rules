rule win_nightclub_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.nightclub."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nightclub"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff4808 83c404 3b7514 75b4 5f 5b 8b450c }
		$sequence_1 = { 8d4dd0 c645f300 ff15???????? 8b4d08 8d45c0 50 51 }
		$sequence_2 = { 8d75bc e8???????? 8d75e0 e8???????? eb33 8b55bc 8b7d08 }
		$sequence_3 = { 8da42400000000 8a4701 47 84c0 75f8 b90b000000 be???????? }
		$sequence_4 = { 83c404 6a00 56 53 8bf8 ff15???????? }
		$sequence_5 = { 85c0 7505 a1???????? 8bc8 8bff 8a10 40 }
		$sequence_6 = { 83c408 8bc8 ff15???????? 5f 5e 8be5 5d }
		$sequence_7 = { 5b b87fe0077e f7ef c1fa08 8bfa c1ef1f 03fa }
		$sequence_8 = { 8b45f0 83c010 83c310 8945f0 3bc6 75dc }
		$sequence_9 = { c645f200 ff15???????? c745e001000000 85db 0f848c010000 8b15???????? 8b450c }

	condition:
		7 of them and filesize <247808
}
