import "pe"

rule MALWARE_Win_Vidar
{
	meta:
		author = "ditekSHen"
		description = "Detects Vidar / ArkeiStealer"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\"os_crypt\":{\"encrypted_key\":\"" fullword ascii
		$s2 = "screenshot.jpg" fullword wide
		$s3 = "Content-Disposition: form-data; name=\"" ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
