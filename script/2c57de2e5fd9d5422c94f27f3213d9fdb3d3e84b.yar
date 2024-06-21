rule Kimsuky_downloader_vbs
{
	meta:
		description = "VBS file to download Powershell used by Kimsuky"
		author = "JPCERT/CC Incident Response Group"
		hash = "36997232fc97040b099fedc4f0c5bf7aed5d468533a27924dc981b94ca208d71"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "PokDoc -Slyer 'xxx'" ascii
		$s2 = "InfoKey -ur 'xxx'" ascii
		$s3 = "iex (wget xxx" ascii
		$s4 = "pow_cmd = Replace(pow_cmd, \"xxx\", uri)" ascii

	condition:
		3 of them
}
