rule remsec_encrypted_api
{
	meta:
		copyright = "Symantec"
		description = "Detects malware from Symantec's Strider APT report"
		score = 80
		date = "2016/08/08"
		reference = "http://www.symantec.com/connect/blogs/strider-cyberespionage-group-turns-eye-sauron-targets"
		os = "windows"
		filetype = "executable"

	strings:
		$open_process = { 91 9A 8F B0 9C 90 8D AF 8C 8C 9A FF }

	condition:
		all of them
}
