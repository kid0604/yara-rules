rule Windows_Ransomware_Ryuk_88daaf8e : beta
{
	meta:
		author = "Elastic Security"
		id = "88daaf8e-0bfe-46c4-9a75-2527d0e10538"
		fingerprint = "b1f218a9bc6bf5f3ec108a471de954988e7692de208e68d7d4ee205194cbbb40"
		creation_date = "2020-04-30"
		last_modified = "2021-08-23"
		description = "Identifies RYUK ransomware"
		threat_name = "Windows.Ransomware.Ryuk"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$f1 = { 48 8B CF E8 AB 25 00 00 85 C0 74 35 }

	condition:
		1 of ($f*)
}
