rule Windows_Ransomware_Doppelpaymer_6660d29f : beta
{
	meta:
		author = "Elastic Security"
		id = "6660d29f-aca9-4156-90a0-ce64fded281a"
		fingerprint = "8bf4d098b8ce9da99a2ca13fa0759a7185ade1b3ab3b281cd15749d68546d130"
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
		$a1 = "Setup run" wide fullword
		$a2 = "RtlComputeCrc32" ascii fullword

	condition:
		2 of ($a*)
}
