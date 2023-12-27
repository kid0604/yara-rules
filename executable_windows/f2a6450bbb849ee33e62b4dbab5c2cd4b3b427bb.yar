rule win_banpolmex_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.banpolmex."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.banpolmex"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 7419 4c8b0f 8bd0 41b801000000 498bcc e8???????? 4883f801 }
		$sequence_1 = { ff15???????? 488d1530980800 488bcb 488905???????? ff15???????? 488d1529980800 488bcb }
		$sequence_2 = { c3 488d15ea560200 488bcf e8???????? b80a000000 488b5c2460 4883c420 }
		$sequence_3 = { 0f97c0 890d???????? 4883c428 c3 8b0d???????? 44891d???????? 3bc1 }
		$sequence_4 = { 448d4201 4d8bb4c5a8010000 488bcb e8???????? 85c0 7919 488d156ca70100 }
		$sequence_5 = { 4d016810 4d016018 49017020 49017828 49015830 4d015838 4d015040 }
		$sequence_6 = { 660f1f440000 483bd5 7733 488bca 4869c988000000 4903c9 428b44210c }
		$sequence_7 = { 4883ec28 488b0d???????? 4885c9 7409 83caff ff15???????? 33c0 }
		$sequence_8 = { 4c8b5c2420 488b442428 4c011b 480107 0fb7442438 66ffc0 6689442438 }
		$sequence_9 = { 4c897c2458 3c02 0f85a4000000 41b803000000 4533ff 898c24a8000000 44898424b0000000 }

	condition:
		7 of them and filesize <1555456
}