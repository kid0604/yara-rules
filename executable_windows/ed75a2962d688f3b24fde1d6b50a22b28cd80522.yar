rule certificate_alt_2
{
	meta:
		author = "x0r"
		description = "Inject certificate in store"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$f1 = "Crypt32.dll" nocase
		$r1 = "software\\microsoft\\systemcertificates\\spc\\certificates" nocase
		$c1 = "CertOpenSystemStore"

	condition:
		all of them
}
