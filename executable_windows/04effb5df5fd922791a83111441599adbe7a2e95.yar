rule create_service
{
	meta:
		author = "x0r"
		description = "Create a windows service"
		version = "0.2"
		os = "windows"
		filetype = "executable"

	strings:
		$f1 = "Advapi32.dll" nocase
		$c1 = "CreateService"
		$c2 = "ControlService"
		$c3 = "StartService"
		$c4 = "QueryServiceStatus"

	condition:
		all of them
}
