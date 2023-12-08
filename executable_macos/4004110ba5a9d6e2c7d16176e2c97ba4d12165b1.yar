rule MachO_File_pyinstaller
{
	meta:
		author = "KatsuragiCSL (https://katsuragicsl.github.io)"
		description = "Detect Mach-O file produced by pyinstaller"
		os = "macos"
		filetype = "executable"

	strings:
		$a = "pyi-runtime-tmpdir"
		$b = "pyi-bootloader-ignore-signals"

	condition:
		any of them
}
