rule APT30_Generic_9
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		super_rule = 1
		hash0 = "00d9949832dc3533592c2ce06a403ef19deddce9"
		hash1 = "27a2b981d4c0bb8c3628bfe990db4619ddfdff74"
		hash2 = "05f66492c163ec2a24c6a87c7a43028c5f632437"
		hash3 = "263f094da3f64e72ef8dc3d02be4fb33de1fdb96"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "%s\\%s\\$NtRecDoc$" fullword
		$s1 = "%s(%u)%s" fullword
		$s2 = "http://%s%s%s" fullword
		$s3 = "1.9.1.17" fullword wide
		$s4 = "(C)Firefox and Mozilla Developers, according to the MPL 1.1/GPL 2.0/LGPL" wide

	condition:
		filesize <250KB and uint16(0)==0x5A4D and all of them
}
