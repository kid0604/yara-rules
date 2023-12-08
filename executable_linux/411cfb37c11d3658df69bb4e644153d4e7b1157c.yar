rule Linux_Exploit_CVE_2016_5195_ab87c1ed
{
	meta:
		author = "Elastic Security"
		id = "ab87c1ed-f538-4785-b7ae-5333a7ff2808"
		fingerprint = "3bf2be85120ef3711dd3508bf8fcd573a70c7ad4a5066be1b60d777a53cd37b6"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2016-5195"
		reference_sample = "c13c32d3a14cbc9c2580b1c76625cce8d48c5ae683230149a3f41640655e7f28"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Linux kernel exploit for CVE-2016-5195"
		filetype = "executable"

	strings:
		$a = { FF FF 88 45 EF 80 7D EF FF 75 D6 B8 ?? ?? 04 08 }

	condition:
		all of them
}
