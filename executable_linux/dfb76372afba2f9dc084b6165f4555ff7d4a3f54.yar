rule Linux_Trojan_Generic_be1757ef
{
	meta:
		author = "Elastic Security"
		id = "be1757ef-cf45-4c00-8d6c-dbb0f44f6efb"
		fingerprint = "0af6b01197b63259d9ecbc24f95b183abe7c60e3bf37ca6ac1b9bc25696aae77"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Generic"
		reference_sample = "f3e4e2b5af9d0c72aae83cec57e5c091a95c549f826e8f13559aaf7d300f6e13"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Generic"
		filetype = "executable"

	strings:
		$a = { 20 54 68 75 20 4D 61 72 20 31 20 31 34 3A 34 34 3A 30 38 20 }

	condition:
		all of them
}
