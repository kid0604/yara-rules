rule CobaltStrike_Resources_Command_Ps1_v2_5_to_v3_7_and_Resources_Compress_Ps1_v3_8_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/command.ps1 for versions 2.5 to v3.7 and resources/compress.ps1 from v3.8 to v4.x"
		hash = "932dec24b3863584b43caf9bb5d0cfbd7ed1969767d3061a7abdc05d3239ed62"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "script"

	strings:
		$ps1 = "$s=New-Object \x49O.MemoryStream(,[Convert]::\x46romBase64String(" nocase
		$ps2 = "));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();" nocase

	condition:
		all of them
}
