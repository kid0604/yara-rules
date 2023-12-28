rule BlackTech_PLEAD_mutex
{
	meta:
		description = "PLEAD malware mutex strings"
		author = "JPCERT/CC Incident Response Group"
		hash = "6a49771dbb9830e1bdba45137c3a1a22d7964df26e02c715dd6e606f8da4e275"
		os = "windows"
		filetype = "executable"

	strings:
		$v1a = "1....%02d%02d%02d_%02d%02d...2"
		$v1b = "1111%02d%02d%02d_%02d%02d2222"
		$v1c = "%02d:%02d:%02d"
		$v1d = "%02d-%02d-%02d"

	condition:
		($v1a or $v1b) and $v1c and $v1d
}
