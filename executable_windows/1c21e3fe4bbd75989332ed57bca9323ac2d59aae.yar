rule win_rising_sun_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.rising_sun."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rising_sun"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c7451ceb6cdf53 c745207d99ebb9 c74524f0924af9 c7452858285d83 c7452cb17b929c c745307d0f2b0f }
		$sequence_1 = { e8???????? ebc9 488bcb 488bc3 488d15e7780100 48c1f805 83e11f }
		$sequence_2 = { 7512 c705????????0d000000 4532ed 44886c2440 4885f6 743f 488bfe }
		$sequence_3 = { c785b4000000e9f05082 c785b8000000e7fa6acb c785bc00000088e87280 c785c000000044604695 c785c4000000920fad47 c785c8000000093f9752 c785cc000000c6aca765 }
		$sequence_4 = { 41b701 44897c244c 488b0d???????? 4885c9 754a 488d0da6900200 48833d????????08 }
		$sequence_5 = { 7412 48837c244808 720a 488b4c2430 }
		$sequence_6 = { c785cc0100003fac63f5 c785d00100000f815702 c785d40100006b20a6d3 c785d8010000ff9108d0 c785dc010000e0acc4b5 c785e0010000272e7346 c785e4010000df0d063e }
		$sequence_7 = { 488b7d18 488bcd e8???????? 498b4cf408 48ffc3 488904cf 488b7c2470 }
		$sequence_8 = { 4533c9 4533c0 33d2 ff15???????? 488bc8 488905???????? 4885c0 }
		$sequence_9 = { ff15???????? ba55000000 85db 7f05 baaa000000 488d8dc0060000 41b800040000 }

	condition:
		7 of them and filesize <409600
}
