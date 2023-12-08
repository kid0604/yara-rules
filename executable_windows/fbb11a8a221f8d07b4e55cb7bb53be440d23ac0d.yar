rule APT_MAL_RU_WIN_Snake_Malware_May23_1
{
	meta:
		author = "Matt Suiche (Magnet Forensics)"
		description = "Hunting Russian Intelligence Snake Malware"
		date = "2023-05-10"
		threat_name = "Windows.Malware.Snake"
		reference = "https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF"
		score = 75
		scan_context = "memory"
		license = "MIT"
		os = "windows"
		filetype = "executable"

	strings:
		$a = { 25 73 23 31 }
		$b = { 25 73 23 32 }
		$c = { 25 73 23 33 }
		$d = { 25 73 23 34 }
		$e = { 2e 74 6d 70 }
		$g = { 2e 73 61 76 }
		$h = { 2e 75 70 64 }

	condition:
		all of them
}
