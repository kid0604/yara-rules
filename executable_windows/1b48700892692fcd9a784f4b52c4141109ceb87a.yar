rule derusbi_kernel_alt_1
{
	meta:
		description = "Derusbi Driver version"
		date = "2015-12-09"
		author = "Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud"
		os = "windows"
		filetype = "executable"

	strings:
		$token1 = "$$$--Hello"
		$token2 = "Wrod--$$$"
		$cfg = "XXXXXXXXXXXXXXX"
		$class = ".?AVPCC_BASEMOD@@"
		$MZ = "MZ"

	condition:
		$MZ at 0 and $token1 and $token2 and $cfg and $class
}
