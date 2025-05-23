rule win_torisma_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.torisma."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.torisma"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 7402 eb05 e9???????? b833280000 }
		$sequence_1 = { e8???????? 3d514b0000 7504 33c0 }
		$sequence_2 = { e8???????? 3d83490000 7507 b883490000 }
		$sequence_3 = { 4889442458 488b442458 4889442430 488b4c2430 e8???????? }
		$sequence_4 = { 50 ff15???????? 8b4dfc 51 6a40 ff15???????? 8945f8 }
		$sequence_5 = { c1e91b 83e101 33d1 8b4508 8b4878 }
		$sequence_6 = { 8b55f4 52 8b4da4 e8???????? }
		$sequence_7 = { 83e101 c1e102 8b9424bc000000 0bd1 }
		$sequence_8 = { 837c246800 740a 8b442430 89442438 eb08 }
		$sequence_9 = { 89442430 488b442450 8b404c 83e001 }
		$sequence_10 = { 817df404810200 760a b8514b0000 e9???????? 8b45f4 }
		$sequence_11 = { b862000000 668945d2 b962000000 66894dd4 ba30000000 }
		$sequence_12 = { 48894c2408 57 4881ecb0000000 48c7842488000000feffffff }

	condition:
		7 of them and filesize <322560
}
