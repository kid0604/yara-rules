rule win_neteagle_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.neteagle."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.neteagle"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 57 6a00 ff15???????? 8b44241c 8d4c2424 6a00 51 }
		$sequence_1 = { 8d4dec e9???????? 8d4dd8 e9???????? 8b45e4 50 }
		$sequence_2 = { 8b4678 8b3d???????? 50 8b4620 6a01 6880000000 }
		$sequence_3 = { 50 6a00 6880000000 51 ffd7 6a01 6a00 }
		$sequence_4 = { c684241c02000002 8b70f8 81fe00010000 7e1d 8bb42424020000 }
		$sequence_5 = { 52 50 ffd5 6a07 8d8c2428010000 68???????? }
		$sequence_6 = { e8???????? 8d4c2420 c644243c01 e8???????? 8b442414 bf???????? 8a10 }
		$sequence_7 = { 8d4c2418 c644245801 e8???????? 8d4c2434 e8???????? 8d542464 }
		$sequence_8 = { 52 8944244c e8???????? 8d4c2414 c644243803 e8???????? }
		$sequence_9 = { 8964242c 51 8d4c2434 e8???????? 8d542428 8bce 52 }

	condition:
		7 of them and filesize <262144
}
