import "pe"

rule MALWARE_Win_NetSupport
{
	meta:
		author = "ditekSHen"
		description = "Detects NetSupport client"
		snort_sid = "920266-920267"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = ":\\nsmsrc\\nsm\\" fullword ascii
		$s2 = "name=\"NetSupport Client Configurator\"" fullword ascii
		$s3 = "<description>NetSupport Manager Remote Control.</description>" fullword ascii

	condition:
		uint16(0)==0x5a4d and 2 of them
}
