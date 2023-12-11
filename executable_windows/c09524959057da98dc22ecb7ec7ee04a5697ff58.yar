rule Windows_Ransomware_Doppelpaymer_4fb1a155 : beta
{
	meta:
		author = "Elastic Security"
		id = "4fb1a155-6448-41e9-829a-e765b7c2570e"
		fingerprint = "f7c1bb3e9d1ad02e7c4edf8accf326330331f92a0f1184bbc19c5bde7505e545"
		creation_date = "2020-06-28"
		last_modified = "2021-08-23"
		description = "Identifies DOPPELPAYMER ransomware"
		threat_name = "Windows.Ransomware.Doppelpaymer"
		reference = "https://www.crowdstrike.com/blog/doppelpaymer-ransomware-and-dridex-2/"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$c1 = { 83 EC 64 8B E9 8B 44 24 ?? 8B 00 0F B7 10 83 FA 5C 75 }

	condition:
		1 of ($c*)
}
