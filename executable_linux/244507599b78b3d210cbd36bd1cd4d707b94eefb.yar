rule Linux_Rootkit_Reptile_85abf958
{
	meta:
		author = "Elastic Security"
		id = "85abf958-1c81-4b65-ae5c-49f3e5137f07"
		fingerprint = "db0f0398bb25e96f2b46d3836fbcc056dc3ac90cfbe6ba6318fd6fa48315432b"
		creation_date = "2024-11-13"
		last_modified = "2024-11-22"
		threat_name = "Linux.Rootkit.Reptile"
		reference_sample = "331494780c1869e8367c3e16a2b99aeadc604c73b87f09a01dda00ade686675b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Rootkit.Reptile"
		filetype = "executable"

	strings:
		$byte1 = { C7 06 65 78 65 63 C7 46 04 20 62 61 73 C7 46 08 68 20 2D 2D C7 46 0C 72 63 66 69 C7 46 10 6C 65 20 00 }
		$byte2 = { C7 07 59 6F 75 20 C7 47 04 61 72 65 20 C7 47 08 61 6C 72 65 C7 47 0C 61 64 79 20 C7 47 10 72 6F 6F 74 C7 47 14 21 20 3A 29 C7 47 18 0A 0A 00 00 }
		$byte3 = { C7 47 08 59 6F 75 20 C7 47 0C 68 61 76 65 C7 47 10 20 6E 6F 20 C7 47 14 70 6F 77 65 C7 47 18 72 20 68 65 C7 47 1C 72 65 21 20 C7 47 20 3A 28 20 1B }
		$byte4 = { C7 47 08 59 6F 75 20 C7 47 0C 67 6F 74 20 C7 47 10 73 75 70 65 C7 47 14 72 20 70 6F C7 47 18 77 65 72 73 C7 47 1C 21 1B 5B 30 C7 47 20 30 6D 0A 0A }
		$byte5 = { C7 06 66 69 6C 65 C7 46 04 2D 74 61 6D C7 46 08 70 65 72 69 C7 46 0C 6E 67 00 00 }
		$str1 = "reptile"
		$str2 = "exec bash --rcfi"

	condition:
		any of ($byte*) or all of ($str*)
}
