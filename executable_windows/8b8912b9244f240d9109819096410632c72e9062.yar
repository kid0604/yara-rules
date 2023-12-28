rule malware_INetGet_exe
{
	meta:
		description = "APT Malware using INetGet"
		author = "JPCERT/CC Incident Response Group"
		hash = "d3f0af5ab7778846d0eafa4c466c11f11e4ee3b0dc359f732ba588c5a482dbf2"
		os = "windows"
		filetype = "executable"

	strings:
		$v1c = "cookie:flag=" wide
		$v1d = "LoRd_MuldeR" wide
		$w1a = "INetGet.exe" wide

	condition:
		all of them
}
