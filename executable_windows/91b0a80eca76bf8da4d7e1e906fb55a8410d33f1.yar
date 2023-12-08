rule Binary_Drop_Certutil
{
	meta:
		description = "Drop binary as base64 encoded cert trick"
		author = "Florian Roth"
		reference = "https://goo.gl/9DNn8q"
		date = "2015-07-15"
		score = 70
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "echo -----BEGIN CERTIFICATE----- >" ascii
		$s1 = "echo -----END CERTIFICATE----- >>" ascii
		$s2 = "certutil -decode " ascii

	condition:
		filesize <10KB and all of them
}
