rule UniformJuliett
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "Cmd03000_1a6f62e1630d512c3b67bfdbff26270177585c82802ffa834b768ff47be0a008.bin"
		description = "Detects the UniformJuliett malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {56 FF D5 68 B8 0B 00 00 FF 15 [4] 6A 00 68 [4] E8 [4] 83 C4 08 68 [4] FF 15}
		$ = "wauserv.dll"
		$ = "Rpcss"

	condition:
		all of them
}
