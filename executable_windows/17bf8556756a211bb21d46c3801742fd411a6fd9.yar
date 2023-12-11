rule Codoso_PGV_PVID_2
{
	meta:
		description = "Detects Codoso APT PGV PVID Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		super_rule = 1
		hash1 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
		hash2 = "b631553421aa17171cc47248adc110ca2e79eff44b5e5b0234d69b30cab104e3"
		hash3 = "bc0b885cddf80755c67072c8b5961f7f0adcaeb67a1a5c6b3475614fd51696fe"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" fullword ascii
		$s1 = "regsvr32.exe /s \"%s\"" fullword ascii
		$s2 = "Help and Support" fullword ascii
		$s3 = "netsvcs" fullword ascii
		$s9 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" fullword ascii
		$s10 = "winlogon" fullword ascii
		$s11 = "System\\CurrentControlSet\\Services" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <907KB and all of them
}
