rule SUSP_Win32dll_String
{
	meta:
		description = "Detects suspicious string in executables"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://medium.com/@Sebdraven/apt-sidewinder-changes-theirs-ttps-to-install-their-backdoor-f92604a2739"
		date = "2018-10-24"
		hash1 = "7bd7cec82ee98feed5872325c2f8fd9f0ea3a2f6cd0cd32bcbe27dbbfd0d7da1"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "win32dll.dll" fullword ascii

	condition:
		filesize <60KB and all of them
}
