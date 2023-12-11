import "pe"

rule HvS_APT27_HyperBro_Stage3
{
	meta:
		description = "HyperBro Stage 3 detection - also tested in memory"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Markus Poelloth"
		reference = "https://www.hvs-consulting.de/en/threat-intelligence-report-emissary-panda-apt27"
		date = "2022-02-07"
		modified = "2023-01-07"
		hash1 = "624e85bd669b97bc55ed5c5ea5f6082a1d4900d235a5d2e2a5683a04e36213e8"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\cmd.exe /A" wide
		$s2 = "vftrace.dll" fullword wide
		$s3 = "msmpeng.exe" fullword wide
		$s4 = "\\\\.\\pipe\\testpipe" fullword wide
		$s5 = "thumb.dat" fullword wide
		$g1 = "%s\\%d.exe" fullword wide
		$g2 = "https://%s:%d/api/v2/ajax" fullword wide
		$g3 = " -k networkservice" fullword wide
		$g4 = " -k localservice" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <300KB and ((4 of ($s*)) or (4 of ($g*)))
}
