rule win_phobos_auto_alt_1
{
	meta:
		description = "Detect the risk  of Ransomware Phobos Rule 2"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 57 ff15???????? 8906 3bc7 7427 57 ff36 }
		$sequence_1 = { 59 6a14 8d4304 50 57 e8???????? }
		$sequence_2 = { ff7508 ffd0 ff75f8 57 e8???????? 59 }
		$sequence_3 = { 0f85b3000000 57 8d44242c 50 be08020000 56 }
		$sequence_4 = { 8945e4 85c0 0f84c2000000 bf???????? be04010000 }
		$sequence_5 = { 8b450c 83c414 85c0 7408 8b0e 8b4c3908 }
		$sequence_6 = { eb05 ff74bc3c 4f ff15???????? 3bfb 75f1 }
		$sequence_7 = { 333c95d0b14000 8b55fc c1ea08 c1eb10 23d0 8b1495d0ad4000 23d8 }
		$sequence_8 = { e8???????? be???????? 8d7c2428 a5 a5 a5 }
		$sequence_9 = { 7703 83c020 c3 55 8bec 57 ff7508 }

	condition:
		7 of them and filesize <139264
}
