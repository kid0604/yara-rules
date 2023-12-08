rule PoetRat_Doc
{
	meta:
		Author = "Nishan Maharjan"
		Description = "A yara rule to catch PoetRat Word Document"
		Data = "6th May 2020"
		description = "A yara rule to catch PoetRat Word Document"
		os = "windows"
		filetype = "document"

	strings:
		$pythonRegEx = /(\.py$|\.pyc$|\.pyd$|Python)/
		$pythonFile1 = "launcher.py"
		$zipFile = "smile.zip"
		$pythonFile2 = "smile_funs.py"
		$pythonFile3 = "frown.py"
		$pythonFile4 = "backer.py"
		$pythonFile5 = "smile.py"
		$pythonFile6 = "affine.py"
		$dlls = /\.dll/
		$cmd = "cmd"
		$exe = ".exe"

	condition:
		all of them
}
