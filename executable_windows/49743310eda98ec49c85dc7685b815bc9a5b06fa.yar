rule APT_DNSpionage_Karkoff_Malware_Apr19_1
{
	meta:
		description = "Detects DNSpionage Karkoff malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.talosintelligence.com/2019/04/dnspionage-brings-out-karkoff.html"
		date = "2019-04-24"
		hash1 = "6a251ed6a2c6a0a2be11f2a945ec68c814d27e2b6ef445f4b2c7a779620baa11"
		hash2 = "b017b9fc2484ce0a5629ff1fed15bca9f62f942eafbb74da6a40f40337187b04"
		hash3 = "5b102bf4d997688268bab45336cead7cdf188eb0d6355764e53b4f62e1cdf30c"
		hash4 = "cd4b9d0f2d1c0468750855f0ed352c1ed6d4f512d66e0e44ce308688235295b5"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Karkoff.exe" fullword wide
		$x2 = "kuternull.com" fullword wide
		$x3 = "rimrun.com" fullword wide
		$s1 = "C:\\Windows\\Temp\\" wide
		$s2 = "CMD.exe" fullword wide
		$s3 = "get_ProcessExtensionDataNames" fullword ascii
		$s4 = "get_ProcessDictionaryKeys" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and (1 of ($x*) or all of ($s*))
}
