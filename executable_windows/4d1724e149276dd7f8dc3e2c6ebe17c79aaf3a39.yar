rule Rombertik_CarbonGrabber_Builder
{
	meta:
		description = "Detects CarbonGrabber alias Rombertik Builder - file Builder.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blogs.cisco.com/security/talos/rombertik"
		date = "2015-05-05"
		hash = "b50ecc0ba3d6ec19b53efe505d14276e9e71285f"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "c:\\users\\iden\\documents\\visual studio 2010\\Projects\\FormGrabberBuilderC++" ascii
		$s1 = "Host(www.panel.com): " fullword ascii
		$s2 = "Path(/form/index.php?a=insert): " fullword ascii
		$s3 = "FileName: " fullword ascii
		$s4 = "~Rich8" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <35KB and all of them
}
