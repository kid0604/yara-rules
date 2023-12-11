rule SUSP_Obfuscted_PowerShell_Code
{
	meta:
		description = "Detects obfuscated PowerShell Code"
		date = "2018-12-13"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/silv0123/status/1073072691584880640"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "').Invoke(" ascii
		$s2 = "(\"{1}{0}\"" ascii
		$s3 = "{0}\" -f" ascii

	condition:
		#s1>11 and #s2>10 and #s3>10
}
