rule win_petya_auto
{
	meta:
		description = "Detect the risk of Ransomware Petya Rule 1"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8d4e28 e8???????? 8d4e4c e8???????? }
		$sequence_1 = { 8bc6 c1e810 88442429 8bc6 c1e808 8844242a }
		$sequence_2 = { 0f42f2 6a04 56 e8???????? 8bd8 }
		$sequence_3 = { 6a04 6a20 c705????????20000000 e8???????? }
		$sequence_4 = { 51 83c050 03c7 53 50 e8???????? }
		$sequence_5 = { e8???????? 8d4e10 e8???????? 8d4e1c e8???????? 8d4e28 e8???????? }
		$sequence_6 = { c7461001000000 33c0 5e 8be5 }
		$sequence_7 = { 8bda c1e60e c1e017 33ff 0bf9 c1eb09 8b4c2424 }
		$sequence_8 = { 7617 53 33db 8b4e74 03cb }
		$sequence_9 = { 8d4e10 e8???????? 8d4e1c e8???????? 8d4e28 e8???????? }

	condition:
		7 of them and filesize <229376
}