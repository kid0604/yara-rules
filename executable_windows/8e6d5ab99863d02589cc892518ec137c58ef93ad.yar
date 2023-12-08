import "pe"

rule rpx_1_xx : Packer
{
	meta:
		author = "Kevin Falcoz"
		date_create = "24/03/2013"
		description = "RPX v1.XX"
		os = "windows"
		filetype = "executable"

	strings:
		$signature1 = "RPX 1."
		$signature2 = "Copyright 20"

	condition:
		$signature1 and $signature2
}
