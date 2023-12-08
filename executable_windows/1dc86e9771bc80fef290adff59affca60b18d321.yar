rule create_com_service
{
	meta:
		author = "x0r"
		description = "Create a COM server"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$c1 = "DllCanUnloadNow" nocase
		$c2 = "DllGetClassObject"
		$c3 = "DllInstall"
		$c4 = "DllRegisterServer"
		$c5 = "DllUnregisterServer"

	condition:
		all of them
}
