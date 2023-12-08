rule Linux_Trojan_Ddostf_6dc1caab
{
	meta:
		author = "Elastic Security"
		id = "6dc1caab-be84-4f27-a059-2acffc20ca2c"
		fingerprint = "43bcb29d92e0ed2dfd0ff182991864f8efabd16a0f87e8c3bb453b47bd8e272b"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Ddostf"
		reference_sample = "f4587bd45e57d4106ebe502d2eaa1d97fd68613095234038d67490e74c62ba70"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Ddostf"
		filetype = "executable"

	strings:
		$a = { FC 01 83 45 F8 01 83 7D F8 5A 7E E6 C7 45 F8 61 00 00 00 EB 14 8B }

	condition:
		all of them
}
