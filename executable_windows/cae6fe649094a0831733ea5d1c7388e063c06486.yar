rule win_makop_ransomware_auto
{
	meta:
		description = "Detect the risk of Ransomware Makop Rule 2"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 6a04 8d542408 52 6a18 50 c744241400000000 ff15???????? }
		$sequence_1 = { 8d442410 e8???????? 6a00 6a00 6a00 6a00 }
		$sequence_2 = { 7403 50 ffd6 8b442410 83f8ff 7403 }
		$sequence_3 = { 57 6a2c 33db 53 ffd6 8b3d???????? }
		$sequence_4 = { 0fb74c1702 83c202 0fb7ee 2bcd 74e8 33ed 3bcd }
		$sequence_5 = { 7420 837c240c08 7219 8b442410 8b4c2414 50 51 }
		$sequence_6 = { 85c0 751a ff15???????? 8b4c2404 51 ff15???????? 32c0 }
		$sequence_7 = { 56 6a00 ffd7 50 ff15???????? 6a08 }
		$sequence_8 = { ffd3 50 ffd7 8b4628 85c0 741a b92c000000 }
		$sequence_9 = { 8b442418 8b542414 8bcf e8???????? 85c0 0f84db020000 8b442414 }

	condition:
		7 of them and filesize <107520
}
