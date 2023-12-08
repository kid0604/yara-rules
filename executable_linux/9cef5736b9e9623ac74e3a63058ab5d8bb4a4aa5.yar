rule Linux_Exploit_Courier_190258dd
{
	meta:
		author = "Elastic Security"
		id = "190258dd-1384-4144-aa05-7957ca0b464b"
		fingerprint = "4ba94b87847a76df80200d40383d2d289dc463faa609237dbc43f317db45074d"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Courier"
		reference_sample = "349866d0fb81d07a35b53eac6f11176721629bbd692526851e483eaa83d690c3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Exploit.Courier"
		filetype = "executable"

	strings:
		$a = { E3 31 C0 50 54 53 50 B0 3B CD 80 31 C0 B0 01 CD }

	condition:
		all of them
}
