rule APT30_Generic_C
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash1 = "8667f635fe089c5e2c666b3fe22eaf3ff8590a69"
		hash2 = "0c4fcef3b583d0ffffc2b14b9297d3a4"
		hash3 = "37aee58655f5859e60ece6b249107b87"
		hash4 = "4154548e1f8e9e7eb39d48a4cd75bcd1"
		hash5 = "a2e0203e665976a13cdffb4416917250"
		hash6 = "b4ae0004094b37a40978ef06f311a75e"
		hash7 = "e39756bc99ee1b05e5ee92a1cdd5faf4"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "MYUSER32.dll" fullword ascii
		$s1 = "MYADVAPI32.dll" fullword ascii
		$s2 = "MYWSOCK32.dll" fullword ascii
		$s3 = "MYMSVCRT.dll" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
