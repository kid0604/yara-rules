rule sig_238_rshsvc
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file rshsvc.bat"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "fb15c31254a21412aecff6a6c4c19304eb5e7d75"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "if not exist %1\\rshsetup.exe goto ERROR2" fullword ascii
		$s1 = "ECHO rshsetup.exe is not found in the %1 directory" fullword ascii
		$s9 = "REM %1 directory must have rshsetup.exe,rshsvc.exe and rshsvc.dll" fullword ascii
		$s10 = "copy %1\\rshsvc.exe" fullword ascii
		$s12 = "ECHO Use \"net start rshsvc\" to start the service." fullword ascii
		$s13 = "rshsetup %SystemRoot%\\system32\\rshsvc.exe %SystemRoot%\\system32\\rshsvc.dll" fullword ascii
		$s18 = "pushd %SystemRoot%\\system32" fullword ascii

	condition:
		all of them
}
