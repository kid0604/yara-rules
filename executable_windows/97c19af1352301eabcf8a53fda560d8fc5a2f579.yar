rule Windows_Trojan_ShadowPad_0d899241
{
	meta:
		author = "Elastic Security"
		id = "0d899241-6ef8-4524-a728-4ed53e4d2cec"
		fingerprint = "7070eb3608c2c39804ccad4a05e4de12ec4eb47388589ef72c723b353b920a68"
		creation_date = "2023-01-31"
		last_modified = "2023-02-01"
		description = "Target ShadowPad payload"
		threat_name = "Windows.Trojan.ShadowPad"
		reference_sample = "cb3a425565b854f7b892e6ebfb3734c92418c83cd590fc1ee9506bcf4d8e02ea"
		severity = 100
		arch_context = "x86"
		scan_context = "memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "hH#whH#w" fullword
		$a2 = "Yuv~YuvsYuvhYuv]YuvRYuvGYuv1:tv<Yuvb#tv1Yuv-8tv&Yuv" fullword
		$a3 = "pH#wpH#w" fullword
		$a4 = "HH#wHH#wA" fullword
		$a5 = "xH#wxH#w:$" fullword
		$re1 = /(HTTPS|TCP|UDP):\/\/[^:]+:443/

	condition:
		4 of them
}
