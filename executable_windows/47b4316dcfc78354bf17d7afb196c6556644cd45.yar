import "pe"

rule APT_FIN7_EXE_Sample_Aug18_5
{
	meta:
		description = "Detects sample from FIN7 report in August 2018"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		date = "2018-08-01"
		hash1 = "7789a3d7d05c30b4efaf3f2f5811804daa56d78a9a660968a4f1f9a78a9108a0"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "x0=%d, y0=%d, x1=%d, y1=%d" fullword ascii
		$s3 = "sdfkjdfjfhgurgvncmnvmfdjdkfjdkfjdf" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <400KB and all of them
}
