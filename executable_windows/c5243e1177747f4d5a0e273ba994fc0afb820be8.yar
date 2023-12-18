rule win_qakbot_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.qakbot."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.qakbot"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c9 c3 55 8bec 81ecc4090000 }
		$sequence_1 = { 33c0 7402 ebfa e8???????? }
		$sequence_2 = { 7402 ebfa 33c0 7402 }
		$sequence_3 = { 7402 ebfa eb06 33c0 }
		$sequence_4 = { e8???????? 33c9 85c0 0f9fc1 41 }
		$sequence_5 = { 50 e8???????? 8b06 47 59 }
		$sequence_6 = { 8d45fc 6aff 50 e8???????? }
		$sequence_7 = { 59 59 33c0 7402 }
		$sequence_8 = { e8???????? 59 59 6afb e9???????? }
		$sequence_9 = { 740d 8d45fc 6a00 50 }
		$sequence_10 = { 50 8d8534f6ffff 6a00 50 e8???????? }
		$sequence_11 = { 8945fc e8???????? 8bf0 8d45fc 50 e8???????? }
		$sequence_12 = { 33c0 e9???????? 33c0 7402 }
		$sequence_13 = { 7402 ebfa e9???????? 6a00 }
		$sequence_14 = { 8975f8 8975f0 8975f4 e8???????? }
		$sequence_15 = { eb0b c644301c00 ff465c 8b465c 83f840 7cf0 }
		$sequence_16 = { 7cef eb10 c644301c00 ff465c 8b465c 83f838 }
		$sequence_17 = { e8???????? 83c410 33c0 7402 }
		$sequence_18 = { 85c0 750a 33c0 7402 }
		$sequence_19 = { c644061c00 ff465c 837e5c38 7cef eb10 c644301c00 }
		$sequence_20 = { 7507 c7466401000000 83f840 7507 }
		$sequence_21 = { 837dfc00 750b 33c0 7402 }
		$sequence_22 = { e8???????? e8???????? 33c0 7402 }
		$sequence_23 = { 833d????????00 7508 33c0 7402 }
		$sequence_24 = { c7466001000000 33c0 40 5e }
		$sequence_25 = { 7402 ebfa 837d1000 7408 }
		$sequence_26 = { 80ea80 8855f0 e8???????? 0fb64df7 }
		$sequence_27 = { 50 8d45d8 50 8d45d4 50 8d45ec }
		$sequence_28 = { 56 e8???????? 8b45fc 83c40c 40 }
		$sequence_29 = { 6a00 6800600900 6a00 ff15???????? }
		$sequence_30 = { 50 ff5508 8bf0 59 }
		$sequence_31 = { 6a00 58 0f95c0 40 50 }
		$sequence_32 = { 57 ff15???????? 33c0 85f6 0f94c0 }
		$sequence_33 = { 750c 57 ff15???????? 6afe 58 }
		$sequence_34 = { c3 33c9 3d80000000 0f94c1 }
		$sequence_35 = { 6a02 ff15???????? 8bf8 83c8ff }
		$sequence_36 = { 50 e8???????? 6a40 8d4590 }
		$sequence_37 = { 8d85e4fcffff 50 8d85e4fdffff 50 }
		$sequence_38 = { 56 e8???????? 83c40c 8d4514 50 }
		$sequence_39 = { e8???????? 6a00 8d45d4 50 68???????? }
		$sequence_40 = { 5d c3 33c9 66890c46 }
		$sequence_41 = { 8b4a04 83c204 03f0 85c9 75e1 }
		$sequence_42 = { 01f1 898424a8000000 899424ac000000 8d8424b4000000 89c2 8db424c4000000 }
		$sequence_43 = { 8a442417 8b4c2410 0485 88440c66 89ca 83c201 }
		$sequence_44 = { ffd3 85ff 741b 6808020000 6a00 }
		$sequence_45 = { 88442401 894c245c 0f847afdffff e9???????? }
		$sequence_46 = { 89442410 884c2417 eb94 55 89e5 31c0 }
		$sequence_47 = { 8945fc 8b4518 53 8b5d10 56 8945c4 }
		$sequence_48 = { 8b742420 81c638a1e7c3 39f0 89442410 894c240c 89542408 7408 }
		$sequence_49 = { 8b74242c bb3c13b648 f7e3 69f63c13b648 01f2 89442428 8954242c }
		$sequence_50 = { 8b4c2444 ffd1 83ec08 b901000000 ba66000000 31ff 89c3 }
		$sequence_51 = { 89e0 89580c bb04000000 895808 8b5c246c 895804 8b9c2480000000 }
		$sequence_52 = { 8bf0 83c40c 85f6 0f84f8000000 a1???????? }

	condition:
		7 of them and filesize <4883456
}
