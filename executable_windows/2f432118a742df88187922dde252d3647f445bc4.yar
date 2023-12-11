rule Windows_Ransomware_Clop_9ac9ea3e : beta
{
	meta:
		author = "Elastic Security"
		id = "9ac9ea3e-72e1-4151-a2f8-87869f5f98e3"
		fingerprint = "1cb0adb36e94ef8f8d74862250205436ed3694ed7719d8e639cfdd0c8632fd6c"
		creation_date = "2020-05-03"
		last_modified = "2021-08-23"
		description = "Identifies CLOP ransomware in unpacked state"
		threat_name = "Windows.Ransomware.Clop"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.clop"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$c1 = { 8B 1D D8 E0 40 00 33 F6 8B 3D BC E0 40 00 }

	condition:
		1 of ($c*)
}
